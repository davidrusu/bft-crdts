/// An implementation of deterministic SecureBroadcast.
use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::actor::{Actor, Sig};
use crate::bft_membership::{self, Generation};
use crate::packet::{Packet, Payload};
use crate::traits::SecureBroadcastAlgorithm;

use crdts::{CmRDT, CvRDT, Dot, VClock};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum Error {
    Membership(bft_membership::Error),
    Encoding(bincode::Error),
}

impl From<bincode::Error> for Error {
    fn from(err: bincode::Error) -> Self {
        Self::Encoding(err)
    }
}

impl From<bft_membership::Error> for Error {
    fn from(err: bft_membership::Error) -> Self {
        Self::Membership(err)
    }
}

#[derive(Debug)]
pub struct SecureBroadcastProc<A: SecureBroadcastAlgorithm> {
    // The identity of a process
    pub membership: bft_membership::State,

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

    // Track number of invalid packets received from an actor
    pub invalid_packets: BTreeMap<Actor, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicatedState<A: SecureBroadcastAlgorithm> {
    pub algo_state: A::ReplicatedState,
    pub delivered: VClock<Actor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Msg<AlgoOp> {
    gen: Generation,
    op: AlgoOp,
    dot: Dot<Actor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op<AlgoOp> {
    RequestValidation {
        msg: Msg<AlgoOp>,
    },
    SignedValidated {
        msg: Msg<AlgoOp>,
        sig: Sig,
    },
    ProofOfAgreement {
        msg: Msg<AlgoOp>,
        proof: BTreeMap<Actor, Sig>,
    },
}

impl<AlgoOp> Payload<AlgoOp> {
    pub fn is_proof_of_agreement(&self) -> bool {
        match self {
            Payload::SecureBroadcast(Op::ProofOfAgreement { .. }) => true,
            _ => false,
        }
    }
}

impl<A: SecureBroadcastAlgorithm> SecureBroadcastProc<A> {
    pub fn new() -> Self {
        let membership = bft_membership::State::default();
        let algo = A::new(membership.id.actor());
        Self {
            membership,
            algo,
            pending_proof: Default::default(),
            delivered: Default::default(),
            received: Default::default(),
            invalid_packets: Default::default(),
        }
    }

    pub fn actor(&self) -> Actor {
        self.membership.id.actor()
    }

    pub fn state(&self) -> ReplicatedState<A> {
        ReplicatedState {
            algo_state: self.algo.state(),
            delivered: self.delivered.clone(),
        }
    }

    pub fn peers(&self) -> Result<BTreeSet<Actor>, Error> {
        self.membership
            .members(self.membership.gen)
            .map_err(Error::Membership)
    }

    pub fn trust_peer(&mut self, peer: Actor) {
        println!("[DSB] {:?} is trusting {:?}", self.actor(), peer);
        self.membership.trust(peer);
    }

    pub fn request_membership(
        &mut self,
        actor: Actor,
    ) -> Result<Vec<Packet<A::Op>>, bft_membership::Error> {
        Ok(self
            .membership
            .propose(bft_membership::Reconfig::Join(actor))?)
    }

    pub fn kill_peer(&mut self, actor: Actor) -> Result<Vec<Packet<A::Op>>, bft_membership::Error> {
        Ok(self
            .membership
            .propose(bft_membership::Reconfig::Leave(actor))?)
    }

    pub fn sync_from(&mut self, state: ReplicatedState<A>) {
        // TODO: !! there is no validation this state right now.
        // Suggestion. Periodic BFT agreement on the state snapshot, and procs store all ProofsOfAgreement msgs they've delivered since last snapshot.
        // once the list of proofs becomes large enough, collapse these proofs into the next snapshot.
        //
        // During onboarding, ship the last snapshot together with it's proof of agreement and the subsequent list of proofs of agreement msgs.
        println!("[DSB] {} syncing", self.actor());
        self.delivered.merge(state.delivered.clone());
        self.received.merge(state.delivered); // We advance received up to what we've delivered
        self.algo.sync_from(state.algo_state);
    }

    pub fn exec_algo_op(
        &self,
        f: impl FnOnce(&A) -> Option<A::Op>,
    ) -> Result<Vec<Packet<A::Op>>, Error> {
        if let Some(op) = f(&self.algo) {
            self.exec_op(op)
        } else {
            println!("[DSB] algo did not produce an op");
            Ok(vec![])
        }
    }

    pub fn read_state<V>(&self, f: impl FnOnce(&A) -> V) -> V {
        f(&self.algo)
    }

    pub fn handle_packet(&mut self, packet: Packet<A::Op>) -> Result<Vec<Packet<A::Op>>, Error> {
        println!(
            "[DSB] handling packet from {}->{}",
            packet.source,
            self.actor()
        );

        if self.validate_packet(&packet)? {
            self.process_packet(packet)
        } else {
            println!("[DSB/INVALID] packet failed validation: {:?}", packet);
            let count = self.invalid_packets.entry(packet.source).or_default();
            *count += 1;
            Ok(vec![])
        }
    }

    fn process_packet(&mut self, packet: Packet<A::Op>) -> Result<Vec<Packet<A::Op>>, Error> {
        match packet.payload {
            Payload::SecureBroadcast(op) => self.process_secure_broadcast_op(packet.source, op),
            Payload::Membership(vote) => {
                self.membership.handle_vote(vote).map_err(Error::Membership)
            }
        }
    }

    fn process_secure_broadcast_op(
        &mut self,
        source: Actor,
        op: Op<A::Op>,
    ) -> Result<Vec<Packet<A::Op>>, Error> {
        match op {
            Op::RequestValidation { msg } => {
                println!("[DSB] request for validation");
                self.received.apply(msg.dot);

                // NOTE: we do not need to store this message, it will be sent back to us
                // with the proof of agreement. Our signature will prevent tampering.
                let sig = self.membership.id.sign(&msg)?;
                let validation = Op::SignedValidated { msg, sig };
                Ok(vec![self.send(source, validation)?])
            }
            Op::SignedValidated { msg, sig } => {
                println!("[DSB] signed validated");
                self.pending_proof
                    .entry(msg.clone())
                    .or_default()
                    .insert(source, sig);

                let num_signatures = self.pending_proof[&msg].len();

                // we don't want to re-broadcast a proof if we've already reached quorum
                // hence we check that (num_sigs - 1) was not quorum
                if self.quorum(num_signatures, msg.gen)?
                    && !self.quorum(num_signatures - 1, msg.gen)?
                {
                    println!("[DSB] we have quorum over msg, sending proof to network");
                    // We have quorum, broadcast proof of agreement to network
                    let proof = self.pending_proof[&msg].clone();

                    // Add ourselves to the broadcast recipients since we may have initiated this request
                    // while we were not yet an accepted member of the network.
                    // e.g. this happens if we request to join the network.
                    let recipients = &self.membership.members(msg.gen).unwrap()
                        | &vec![self.actor()].into_iter().collect();
                    self.broadcast(&Op::ProofOfAgreement { msg, proof }, recipients)
                } else {
                    Ok(vec![])
                }
            }
            Op::ProofOfAgreement { msg, .. } => {
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
                self.algo.apply(msg.op);

                // TODO: Once we relax our network assumptions, we must put in an ack
                // here so that the source knows that honest procs have applied the transaction
                Ok(vec![])
            }
        }
    }

    fn validate_packet(&self, packet: &Packet<A::Op>) -> Result<bool, Error> {
        if !packet.source.verify(&packet.payload, &packet.sig)? {
            println!(
                "[DSB/SIG] Msg failed signature verification {}->{}",
                packet.source,
                self.actor(),
            );
            Ok(false)
        } else if !self.validate_payload(packet.source, &packet.payload)? {
            println!(
                "[DSB/BFT] Msg failed validation {}->{}",
                packet.source,
                self.actor()
            );
            Ok(false)
        } else {
            Ok(true)
        }
    }

    fn validate_payload(&self, from: Actor, payload: &Payload<A::Op>) -> Result<bool, Error> {
        match payload {
            Payload::SecureBroadcast(op) => self.validate_secure_broadcast_op(from, op),
            Payload::Membership(_) => Ok(true), // membership votes are validated inside membership.handle_vote(..)
        }
    }

    fn validate_secure_broadcast_op(&self, from: Actor, op: &Op<A::Op>) -> Result<bool, Error> {
        let validation_tests = match op {
            Op::RequestValidation { msg } => vec![
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
		    msg.gen == self.membership.gen,
		    "This message is from a different generation".to_string(),
		),
		(
                    self.membership.members(self.membership.gen)?.contains(&from),
                    "source is not a voting member of the network".to_string(),
                ),
                (self.algo.validate(&from, &msg.op), "failed algo validation".to_string())
            ],
            Op::SignedValidated { msg, sig } => vec![
                (
                    from.verify(&msg, sig)?,
                    "failed sig verification".to_string(),
                ),
                (
                    self.actor() == msg.dot.actor,
                    "validation not requested".to_string(),
                ),
            ],
            Op::ProofOfAgreement { msg, proof } => {
                let msg_members = self.membership.members(msg.gen)?;
                vec![
                    (
                        self.delivered.inc(from) == msg.dot,
                        format!(
                            "either already delivered or out of order msg: {:?} != {:?}",
                            self.delivered.inc(from),
                            msg.dot
                        ),
                    ),
                    (
                        self.quorum(proof.len(), msg.gen)?,
                        "not enough signatures for quorum".to_string(),
                    ),
                    (
                        proof
                            .iter()
                            .all(|(signatory, _sig)| msg_members.contains(&signatory)),
                        "proof contains signature(s) from unknown peer(s)".to_string(),
                    ),
                    (
                        proof
                            .iter()
                            .map(|(signatory, sig)| signatory.verify(&msg, &sig))
                            .collect::<Result<Vec<bool>, _>>()?
                            .into_iter()
                            .all(|v| v),
                        "proof contains invalid signature(s)".to_string(),
                    ),
                ]
            }
        };

        Ok(validation_tests
            .into_iter()
            .find(|(is_valid, _msg)| !is_valid)
            .map(|(_test, msg)| println!("[DSB/INVALID] {} {:?}", msg, op))
            .is_none())
    }

    fn exec_op(&self, op: A::Op) -> Result<Vec<Packet<A::Op>>, Error> {
        let msg = Msg {
            op,
            gen: self.membership.gen,
            // We use the received clock to allow for many operations from this process
            // to be pending agreement at any one point in time.
            dot: self.received.inc(self.actor()),
        };

        println!("[DSB] {} initiating bft for msg {:?}", self.actor(), msg);
        self.broadcast(&Op::RequestValidation { msg }, self.peers()?)
    }

    fn quorum(&self, n: usize, gen: Generation) -> Result<bool, Error> {
        Ok(n * 3 > self.membership.members(gen)?.len() * 2)
    }

    fn broadcast(
        &self,
        op: &Op<A::Op>,
        targets: BTreeSet<Actor>,
    ) -> Result<Vec<Packet<A::Op>>, Error> {
        println!("[DSB] broadcasting {}->{:?}", self.actor(), targets);

        targets
            .into_iter()
            .map(|dest_p| self.send(dest_p, op.clone()))
            .collect()
    }

    fn send(&self, dest: Actor, op: Op<A::Op>) -> Result<Packet<A::Op>, Error> {
        let payload = Payload::SecureBroadcast(op);
        let sig = self.membership.id.sign(&payload)?;
        Ok(Packet {
            source: self.actor(),
            dest,
            payload,
            sig,
        })
    }
}
