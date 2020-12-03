/// An implementation of deterministic SecureBroadcast.
use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::actor::{SigningActor, Actor, Sig};
use crate::traits::SecureBroadcastAlgorithm;

use crdts::{CmRDT, CvRDT, Dot, VClock};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct SecureBroadcastProc<A: SecureBroadcastAlgorithm> {
    // The identity of a process
    pub identity: SigningActor,

    // Msgs this process has initiated and is waiting on BFT agreement for from the network.
    pub pending_proof: HashMap<Msg<A::Op>, BTreeMap<Actor, Sig>>,

    // The clock representing the most recently received messages from each process.
    // These are messages that have been acknowledged but not yet
    // This clock must at all times be greator or equal to the `delivered` clock.
    pub received: VClock<Actor>,

    // The clock representing the most recent msgs we've delivered to the underlying algorithm `algo`.
    pub delivered: VClock<Actor>,

    // The state of the algorithm that we are running BFT over.
    // This can be the causal bank described in AT2, or it can be a CRDT.
    pub algo: A,

    // The set of members in this network.
    pub peers: BTreeSet<Actor>,

    // Track number of invalid packets received from an actor
    pub invalid_packets: BTreeMap<Actor, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicatedState<A: SecureBroadcastAlgorithm> {
    pub algo_state: A::ReplicatedState,
    pub peers: BTreeSet<Actor>,
    pub delivered: VClock<Actor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet<Op> {
    pub source: Actor,
    pub dest: Actor,
    pub payload: Payload<Op>,
    pub sig: Sig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Payload<Op> {
    RequestValidation {
        msg: Msg<Op>,
    },
    SignedValidated {
        msg: Msg<Op>,
        sig: Sig,
    },
    ProofOfAgreement {
        msg: Msg<Op>,
        proof: BTreeMap<Actor, Sig>,
    },
}

impl<Op> Payload<Op> {
    pub fn is_proof_of_agreement(&self) -> bool {
        match self {
            Payload::ProofOfAgreement { .. } => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct Msg<Op> {
    op: BFTOp<Op>,
    dot: Dot<Actor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
enum BFTOp<Op> {
    MembershipNewPeer(Actor),
    MembershipKillPeer(Actor),
    AlgoOp(Op),
}

impl<A: SecureBroadcastAlgorithm> SecureBroadcastProc<A> {
    pub fn new() -> Self {
	let identity = SigningActor::default();
	let algo = A::new(identity.actor());
        Self {
            identity,
            pending_proof: Default::default(),
            algo,
            peers: Default::default(),
            delivered: Default::default(),
            received: Default::default(),
            invalid_packets: Default::default(),
        }
    }

    pub fn actor(&self) -> Actor {
	self.identity.actor()
    }

    pub fn state(&self) -> ReplicatedState<A> {
        ReplicatedState {
            algo_state: self.algo.state(),
            peers: self.peers.clone(),
            delivered: self.delivered.clone(),
        }
    }

    pub fn peers(&self) -> BTreeSet<Actor> {
        self.peers.clone()
    }

    pub fn trust_peer(&mut self, peer: Actor) {
        println!("[DSB] {:?} is trusting {:?}", self.actor(), peer);
        self.peers.insert(peer);
    }

    pub fn request_membership(&self) -> Vec<Packet<A::Op>> {
        self.exec_bft_op(BFTOp::MembershipNewPeer(self.actor()))
    }

    pub fn kill_peer(&self, actor: Actor) -> Vec<Packet<A::Op>> {
        self.exec_bft_op(BFTOp::MembershipKillPeer(actor))
    }

    pub fn sync_from(&mut self, state: ReplicatedState<A>) {
        // TODO: !! there is no validation this state right now.
        // Suggestion. Periodic BFT agreement on the state snapshot, and procs store all ProofsOfAgreement msgs they've delivered since last snapshot.
        // once the list of proofs becomes large enough, collapse these proofs into the next snapshot.
        //
        // During onboarding, ship the last snapshot together with it's proof of agreement and the subsequent list of proofs of agreement msgs.
        println!("[DSB] {} syncing", self.actor());
        self.peers.extend(state.peers);
        self.delivered.merge(state.delivered.clone());
        self.received.merge(state.delivered); // We advance received up to what we've delivered
        self.algo.sync_from(state.algo_state);
    }

    pub fn exec_algo_op(&self, f: impl FnOnce(&A) -> Option<A::Op>) -> Vec<Packet<A::Op>> {
        if let Some(op) = f(&self.algo) {
            self.exec_bft_op(BFTOp::AlgoOp(op))
        } else {
            println!("[DSB] algo did not produce an op");
            vec![]
        }
    }

    pub fn read_state<V>(&self, f: impl FnOnce(&A) -> V) -> V {
        f(&self.algo)
    }

    pub fn apply(&mut self, packet: Packet<A::Op>) -> Vec<Packet<A::Op>> {
        self.handle_packet(packet)
        // TODO: replace handle_packet with apply
    }

    pub fn handle_packet(&mut self, packet: Packet<A::Op>) -> Vec<Packet<A::Op>> {
        println!(
            "[DSB] handling packet from {}->{}",
            packet.source,
            self.actor()
        );

        if self.validate_packet(&packet) {
            self.process_packet(packet)
        } else {
            println!("[DSB/INVALID] packet failed validation: {:?}", packet);
            let count = self.invalid_packets.entry(packet.source).or_default();
            *count += 1;
            vec![]
        }
    }

    fn process_packet(&mut self, packet: Packet<A::Op>) -> Vec<Packet<A::Op>> {
        match packet.payload {
            Payload::RequestValidation { msg } => {
                println!("[DSB] request for validation");
                self.received.apply(msg.dot);

                // NOTE: we do not need to store this message, it will be sent back to us
                // with the proof of agreement. Our signature will prevent tampering.
                let sig = self.identity.sign(&msg);
                let validation = Payload::SignedValidated { msg, sig };
                vec![self.send(packet.source, validation)]
            }
            Payload::SignedValidated { msg, sig } => {
                println!("[DSB] signed validated");
                self.pending_proof
                    .entry(msg.clone())
                    .or_default()
                    .insert(packet.source, sig);

                let num_signatures = self.pending_proof[&msg].len();

                assert!(num_signatures > 0);

                // we don't want to re-broadcast a proof if we've already reached quorum
                // hence we check that (num_sigs - 1) was not quorum
                if self.quorum(num_signatures) && !self.quorum(num_signatures - 1) {
                    println!("[DSB] we have quorum over msg, sending proof to network");
                    // We have quorum, broadcast proof of agreement to network
                    let proof = self.pending_proof[&msg].clone();

                    // Add ourselves to the broadcast recipients since we may have initiated this request
                    // while we were not yet an accepted member of the network.
                    // e.g. this happens if we request to join the network.
                    let recipients = &self.peers | &vec![self.actor()].into_iter().collect();
                    let packets =
                        self.broadcast(&Payload::ProofOfAgreement { msg, proof }, recipients);

                    packets
                } else {
                    vec![]
                }
            }
            Payload::ProofOfAgreement { msg, .. } => {
                println!("[DSB] proof of agreement: {:?}", msg);
                // We may not have been in the subset of members to validate this clock
                // so we may not have had the chance to increment received. We must bring
                // received up to this msg's timestamp.
                //
                // Otherwise we won't be able to validate any future messages
                // from this source.
                self.received.apply(msg.dot);
                self.delivered.apply(msg.dot);

                // Apply the op
                // TODO: factor this out into an apply() method
                match msg.op {
                    BFTOp::MembershipNewPeer(id) => {
                        self.peers.insert(id);
                        // do we want to do some sort of onboarding here?
                        // ie. maybe we can send this new peer our state
                    }
                    BFTOp::MembershipKillPeer(id) => {
                        self.peers.remove(&id);
                    }
                    BFTOp::AlgoOp(op) => self.algo.apply(op),
                };

                // TODO: Once we relax our network assumptions, we must put in an ack
                // here so that the source knows that honest procs have applied the transaction
                vec![]
            }
        }
    }

    fn validate_packet(&self, packet: &Packet<A::Op>) -> bool {
        if !packet.source.verify(&packet.payload, &packet.sig) {
            println!(
                "[DSB/SIG] Msg failed signature verification {}->{}",
                packet.source,
                self.actor(),
            );
            false
        } else if !self.validate_payload(packet.source, &packet.payload) {
            println!(
                "[DSB/BFT] Msg failed validation {}->{}",
                packet.source,
                self.actor()
            );
            false
        } else {
            true
        }
    }

    fn validate_payload(&self, from: Actor, payload: &Payload<A::Op>) -> bool {
        let validation_tests = match payload {
            Payload::RequestValidation { msg } => vec![
                (
                    from == msg.dot.actor,
                    "source does not match the msg dot".to_string(),
                ),
                (
                    msg.dot == self.received.inc(from),
                    "not the next msg".to_string(),
                ),
                (
                    msg.dot == self.delivered.inc(from),
                    "source already has a pending operation, we must wait for that one to complete."
                        .to_string(),
                ),
                (
                    self.validate_bft_op(&from, &msg.op),
                    "failed bft op validation".to_string(),
                ),
            ],
            Payload::SignedValidated { msg, sig } => vec![
                (
                    from.verify(&msg, sig),
                    "failed sig verification".to_string(),
                ),
                (
                    self.actor() == msg.dot.actor,
                    "validation not requested".to_string(),
                ),
            ],
            Payload::ProofOfAgreement { msg, proof } => vec![
                (
                    self.delivered.inc(from) == msg.dot,
                    format!(
                        "either already delivered or out of order msg: {:?} != {:?}",
                        self.delivered.inc(from),
                        msg.dot
                    ),
                ),
                (
                    self.quorum(proof.len()),
                    "not enough signatures for quorum".to_string(),
                ),
                (
                    proof
                        .iter()
                        .all(|(signatory, _sig)| self.peers.contains(&signatory)),
                    "proof contains signature(s) from unknown peer(s)".to_string(),
                ),
                (
                    proof
                        .iter()
                        .all(|(signatory, sig)| signatory.verify(&msg, &sig)),
                    "proof contains invalid signature(s)".to_string(),
                ),
            ],
        };

        validation_tests
            .into_iter()
            .find(|(is_valid, _msg)| !is_valid)
            .map(|(_test, msg)| println!("[DSB/INVALID] {} {:?}", msg, payload))
            .is_none()
    }

    fn validate_bft_op(&self, from: &Actor, bft_op: &BFTOp<A::Op>) -> bool {
        let validation_tests = match bft_op {
            BFTOp::MembershipNewPeer(_id) => vec![], // In a proper deployment, add some validations to resist Sybil attacks
            BFTOp::MembershipKillPeer(_id) => vec![], // We need to validate that this peer has indeed done something worth killing over
            BFTOp::AlgoOp(op) => vec![
                (
                    self.peers.contains(&from),
                    "source is not a voting member of the network",
                ),
                (self.algo.validate(&from, &op), "failed algo validation"),
            ],
        };

        validation_tests
            .into_iter()
            .find(|(is_valid, _msg)| !is_valid)
            .map(|(_test, msg)| println!("[DSB/BFT_OP/INVALID] {} {:?}, {:?}", msg, bft_op, self))
            .is_none()
    }

    fn exec_bft_op(&self, bft_op: BFTOp<A::Op>) -> Vec<Packet<A::Op>> {
        let msg = Msg {
            op: bft_op,
            // We use the received clock to allow for many operations from this process
            // to be pending agreement at any one point in time.
            dot: self.received.inc(self.actor()),
        };

        println!("[DSB] {} initiating bft for msg {:?}", self.actor(), msg);
        self.broadcast(&Payload::RequestValidation { msg }, self.peers.clone())
    }

    fn quorum(&self, n: usize) -> bool {
        n * 3 > self.peers.len() * 2
    }

    fn broadcast(&self, payload: &Payload<A::Op>, targets: BTreeSet<Actor>) -> Vec<Packet<A::Op>> {
        println!("[DSB] broadcasting {}->{:?}", self.actor(), targets);

        targets
            .into_iter()
            .map(|dest_p| self.send(dest_p, payload.clone()))
            .collect()
    }

    fn send(&self, dest: Actor, payload: Payload<A::Op>) -> Packet<A::Op> {
        let sig = self.identity.sign(&payload);
        Packet {
            source: self.actor(),
            dest,
            payload,
            sig,
        }
    }
}
