/// An implementation of deterministic SecureBroadcast.
use std::collections::{HashMap, HashSet};

use crate::at2::identity::{Identity, Sig};
use crate::at2::traits::SecureBroadcastAlgorithm;

use crdts::{CmRDT, CvRDT, Dot, VClock};
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use serde::Serialize;
use sha2::Sha512;

#[derive(Debug)]
pub struct SecureBroadcastProc<A: SecureBroadcastAlgorithm> {
    // The identity of a process is it's keypair
    keypair: Keypair,

    // Msgs this process has initiated and is waiting on BFT agreement for from the network.
    pending_proof: HashMap<Msg<A::Op>, HashMap<Identity, Sig>>,

    // The clock representing the most recently received messages from each process.
    // These are messages that have been acknowledged but not yet
    // This clock must at all times be greator or equal to the `delivered` clock.
    received: VClock<Identity>,

    // The clock representing the most recent msgs we've delivered to the underlying algorithm `algo`.
    delivered: VClock<Identity>,

    // The state of the algorithm that we are running BFT over.
    // This can be the causal bank described in AT2, or it can be a CRDT.
    algo: A,

    // The set of members in this network.
    peers: HashSet<Identity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReplicatedState<A: SecureBroadcastAlgorithm> {
    algo_state: A::ReplicatedState,
    peers: HashSet<Identity>,
    delivered: VClock<Identity>,
}

#[derive(Debug, Clone)]
pub struct Packet<Op> {
    pub source: Identity,
    pub dest: Identity,
    pub payload: Payload<Op>,
    pub sig: Sig,
}

#[derive(Debug, Clone, Serialize)]
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
        proof: HashMap<Identity, Sig>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Hash)]
pub struct Msg<Op> {
    op: BFTOp<Op>,
    dot: Dot<Identity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Hash)]
enum BFTOp<Op> {
    // TODO: support peers leaving
    MembershipNewPeer(Identity),
    AlgoOp(Op),
}

impl<A: SecureBroadcastAlgorithm> SecureBroadcastProc<A> {
    pub fn new(known_peers: HashSet<Identity>) -> Self {
        let mut csprng = OsRng::new().unwrap();
        let keypair = Keypair::generate::<Sha512, _>(&mut csprng);
        let identity = Identity(keypair.public);

        let peers = if known_peers.is_empty() {
            // This is the genesis proc. It must be treated as a special case.
            //
            // Under normal conditions when a proc joins an existing network, it will only
            // add itself to it's own peer set once it receives confirmation from the rest
            // of the network that it has been accepted as a member of the network.
            std::iter::once(identity).collect()
        } else {
            known_peers
        };

        Self {
            keypair,
            pending_proof: HashMap::new(),
            algo: A::new(identity),
            peers,
            delivered: VClock::new(),
            received: VClock::new(),
        }
    }

    pub fn identity(&self) -> Identity {
        Identity(self.keypair.public)
    }

    pub fn state(&self) -> ReplicatedState<A> {
        ReplicatedState {
            algo_state: self.algo.state(),
            peers: self.peers.clone(),
            delivered: self.delivered.clone(),
        }
    }

    pub fn peers(&self) -> HashSet<Identity> {
        self.peers.clone()
    }

    pub fn request_membership(&self) -> Vec<Packet<A::Op>> {
        self.exec_bft_op(BFTOp::MembershipNewPeer(self.identity()))
    }

    pub fn sync_from(&mut self, state: ReplicatedState<A>) {
        // TODO: !! there is no validation this state right now.
        // Suggestion. Periodic BFT agreement on the state snapshot, and procs store all ProofsOfAgreement msgs they've delivered since last snapshot.
        // once the list of proofs becomes large enough, collapse these proofs into the next snapshot.
        //
        // During onboarding, ship the last snapshot together with it's proof of agreement and the subsequent list of proofs of agreement msgs.
        println!("{} syncing", self.identity());
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

    pub fn handle_packet(&mut self, packet: Packet<A::Op>) -> Vec<Packet<A::Op>> {
        println!(
            "[DSB] handling packet from {}->{}",
            packet.source,
            self.identity()
        );
        if !self.verify_sig(&packet.source, &packet.payload, &packet.sig) {
            println!(
                "[DSB] Msg failed verification {}->{}",
                packet.source,
                self.identity(),
            );
            return vec![];
        }

        if !self.validate_payload(packet.source, &packet.payload) {
            println!(
                "[DSB/BFT] Msg failed validation {}->{}",
                packet.source,
                self.identity()
            );
            return vec![];
        }

        match packet.payload {
            Payload::RequestValidation { msg } => {
                println!("[DSB] request for validation");
                self.received.apply(msg.dot);

                // NOTE: we do not need to store this message, it will be sent back to us
                // with the proof of agreement. Our signature will prevent tampering.
                let sig = self.sign(&msg);
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

                if self.quorum(num_signatures) {
                    println!("[DSB] we have quorum over msg, sending proof to network");
                    // We have quorum, broadcast proof of agreement to network
                    let proof = self.pending_proof[&msg].clone();
                    self.broadcast(Payload::ProofOfAgreement { msg, proof })
                } else {
                    vec![]
                }
            }
            Payload::ProofOfAgreement { msg, .. } => {
                println!("[DSB] proof of agreement");
                self.delivered.apply(msg.dot);

                // Apply the op
                // TODO: factor this out into an apply() method
                match msg.op {
                    BFTOp::MembershipNewPeer(id) => {
                        self.peers.insert(id);
                        // do we want to do some sort of onboarding here?
                        // ie. maybe we can send this new peer our state
                    }
                    BFTOp::AlgoOp(op) => self.algo.apply(op),
                };

                // TODO: Once we relax our network assumptions, we must put in an ack
                // here so that the source knows that honest procs have applied the transaction
                vec![]
            }
        }
    }

    fn validate_payload(&self, from: Identity, payload: &Payload<A::Op>) -> bool {
        let validation_tests = match payload {
            Payload::RequestValidation { msg } => vec![
                (from == msg.dot.actor, "source does not match the msg dot"),
                (msg.dot == self.received.inc(from), "not the next msg"),
                (
                    self.validate_bft_op(&from, &msg.op),
                    "failed bft op validation",
                ),
            ],
            Payload::SignedValidated { msg, sig } => vec![
                (self.verify_sig(&from, &msg, sig), "failed sig verification"),
                (self.identity() == msg.dot.actor, "validation not requested"),
            ],
            Payload::ProofOfAgreement { msg, proof } => vec![
                (
                    self.delivered.inc(from) == msg.dot,
                    "either already delivered or out of order msg",
                ),
                (self.quorum(proof.len()), "not enough signatures for quorum"),
                (
                    proof
                        .iter()
                        .all(|(signatory, _sig)| self.peers.contains(&signatory)),
                    "proof contains signature(s) from unknown peer(s)",
                ),
                (
                    proof
                        .iter()
                        .all(|(signatory, sig)| self.verify_sig(signatory, &msg, &sig)),
                    "proof contains invalid signature(s)",
                ),
            ],
        };

        validation_tests
            .into_iter()
            .find(|(is_valid, _msg)| !is_valid)
            .map(|(_test, msg)| println!("[DSB/INVALID] {} {:?}, {:?}", msg, payload, self))
            .is_none()
    }

    fn validate_bft_op(&self, from: &Identity, bft_op: &BFTOp<A::Op>) -> bool {
        let validation_tests = match bft_op {
            BFTOp::MembershipNewPeer(id) => {
                vec![(!self.peers.contains(&id), "peer already exists")]
            }
            BFTOp::AlgoOp(op) => vec![(self.algo.validate(&from, &op), "failed algo validation")],
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
            dot: self.received.inc(self.identity()),
        };

        println!("[DSB] {} initiating bft for msg {:?}", self.identity(), msg);
        self.broadcast(Payload::RequestValidation { msg })
    }

    fn quorum(&self, n: usize) -> bool {
        // TODO: We don't have anti-entropy fully worked out yet so to simplify things,
        // lets wait for the entire network to sign our messages.
        //
        // n * 3 >= self.peers.len() * 2
        n >= self.peers.len()
    }

    fn broadcast(&self, payload: Payload<A::Op>) -> Vec<Packet<A::Op>> {
        println!("[DSB] broadcasting {}->{:?}", self.identity(), self.peers());

        self.peers
            .iter()
            .cloned()
            .map(|dest_p| self.send(dest_p, payload.clone()))
            .collect()
    }

    fn send(&self, dest: Identity, payload: Payload<A::Op>) -> Packet<A::Op> {
        let sig = self.sign(&payload);
        Packet {
            source: self.identity(),
            dest,
            payload,
            sig,
        }
    }

    fn sign(&self, blob: impl Serialize) -> Sig {
        let blob_bytes = bincode::serialize(&blob).expect("Failed to serialize");
        let blob_sig = self.keypair.sign::<Sha512>(&blob_bytes);

        Sig(blob_sig)
    }

    fn verify_sig(&self, source: &Identity, blob: impl Serialize, sig: &Sig) -> bool {
        let blob_bytes = bincode::serialize(&blob).expect("Failed to serialize");
        source.0.verify::<Sha512>(&blob_bytes, &sig.0).is_ok()
    }
}
