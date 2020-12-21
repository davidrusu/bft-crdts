/// An implementation of deterministic SecureBroadcast.
use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::actor::{Actor, Sig};
use crate::bft_membership::{self, Generation};
use crate::packet::{Packet, Payload};
use crate::traits::SecureBroadcastAlgorithm;

use crdts::{CmRDT, CvRDT, Dot, VClock};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("error while processing membership change")]
    Membership(#[from] bft_membership::Error),
    #[error("Failed to serialize all or part of a packet")]
    Encoding(#[from] bincode::Error),
    #[error("Packet failed validation")]
    Validation(#[from] Validation),
}

#[derive(Error, Debug)]
pub enum Validation {
    #[error("The actor `{from}` who sent this packet is different from the actor who incremented the dot: `{dot:?}`")]
    PacketSourceIsNotDot { from: Actor, dot: Dot<Actor> },
    #[error("The dot in this message `{msg_dot:?}` is out of order (expected: {expected_dot:?})")]
    MsgDotNotTheNextDot {
        msg_dot: Dot<Actor>,
        expected_dot: Dot<Actor>,
    },
    #[error("The source of this message already has a pending message, we can not start a new operation until the first one has completed")]
    SourceAlreadyHasPendingMsg {
        msg_dot: Dot<Actor>,
        next_deliver_dot: Dot<Actor>,
    },
    #[error("This message is not from this generation {msg_gen} (expected: {gen})")]
    MessageFromDifferentGeneration {
        msg_gen: Generation,
        gen: Generation,
    },
    #[error("Source is not a voting member ({from:?} not in {members:?})")]
    SourceIsNotVotingMember {
        from: Actor,
        members: BTreeSet<Actor>,
    },
    #[error("the algorithm failed to validated the operation")]
    AlgoValidationFailed,
    #[error("Signature is invalid")]
    InvalidSignature,
    #[error("We received a SignedValidated packet for a message we did not request")]
    SignedValidatedForPacketWeDidNotRequest,
    #[error("Message dot {msg_dot:?} to be applied is not the next message to be delivered (expected: {expected_dot:?}")]
    MsgDotNotNextDotToBeDelivered {
        msg_dot: Dot<Actor>,
        expected_dot: Dot<Actor>,
    },
    #[error("The proof did not contain enough signatures to form quorum")]
    NotEnoughSignaturesToFormQuorum,
    #[error("Proof contains signatures from non-members")]
    ProofContainsSignaturesFromNonMembers,
    #[error("Proof contains invalid signatures")]
    ProofContainsInvalidSignatures,
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

        self.validate_packet(&packet)?;
        self.process_packet(packet)
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

    fn validate_packet(&self, packet: &Packet<A::Op>) -> Result<(), Error> {
        if !packet.source.verify(&packet.payload, &packet.sig)? {
            println!(
                "[DSB/SIG] Msg failed signature verification {}->{}",
                packet.source,
                self.actor(),
            );
            Err(Error::Validation(Validation::InvalidSignature))
        } else {
            self.validate_payload(packet.source, &packet.payload)
        }
    }

    fn validate_payload(&self, from: Actor, payload: &Payload<A::Op>) -> Result<(), Error> {
        match payload {
            Payload::SecureBroadcast(op) => self.validate_secure_broadcast_op(from, op),
            Payload::Membership(_) => Ok(()), // membership votes are validated inside membership.handle_vote(..)
        }
    }

    fn validate_secure_broadcast_op(&self, from: Actor, op: &Op<A::Op>) -> Result<(), Error> {
        match op {
            Op::RequestValidation { msg } => {
                if from != msg.dot.actor {
                    Err(Validation::PacketSourceIsNotDot {
                        from,
                        dot: msg.dot.clone(),
                    })
                } else if msg.dot != self.received.inc(from) {
                    Err(Validation::MsgDotNotTheNextDot {
                        msg_dot: msg.dot,
                        expected_dot: self.received.inc(from),
                    })
                } else if msg.dot != self.delivered.inc(from) {
                    Err(Validation::SourceAlreadyHasPendingMsg {
                        msg_dot: msg.dot,
                        next_deliver_dot: self.delivered.inc(from),
                    })
                } else if msg.gen != self.membership.gen {
                    Err(Validation::MessageFromDifferentGeneration {
                        msg_gen: msg.gen,
                        gen: self.membership.gen,
                    })
                } else if !self
                    .membership
                    .members(self.membership.gen)?
                    .contains(&from)
                {
                    Err(Validation::SourceIsNotVotingMember {
                        from,
                        members: self.membership.members(self.membership.gen)?,
                    })
                } else if !self.algo.validate(&from, &msg.op) {
                    Err(Validation::AlgoValidationFailed)
                } else {
                    Ok(())
                }
            }
            Op::SignedValidated { msg, sig } => {
                if !from.verify(&msg, sig)? {
                    Err(Validation::InvalidSignature)
                } else if self.actor() != msg.dot.actor {
                    Err(Validation::SignedValidatedForPacketWeDidNotRequest)
                } else {
                    Ok(())
                }
            }
            Op::ProofOfAgreement { msg, proof } => {
                let msg_members = self.membership.members(msg.gen)?;
                if self.delivered.inc(from) != msg.dot {
                    Err(Validation::MsgDotNotNextDotToBeDelivered {
                        msg_dot: msg.dot.clone(),
                        expected_dot: self.delivered.inc(from),
                    })
                } else if !self.quorum(proof.len(), msg.gen)? {
                    Err(Validation::NotEnoughSignaturesToFormQuorum)
                } else if !proof
                    .iter()
                    .all(|(signer, _)| msg_members.contains(&signer))
                {
                    Err(Validation::ProofContainsSignaturesFromNonMembers)
                } else if !proof
                    .iter()
                    .map(|(signer, sig)| signer.verify(&msg, &sig))
                    .collect::<Result<Vec<bool>, _>>()?
                    .into_iter()
                    .all(|v| v)
                {
                    Err(Validation::ProofContainsInvalidSignatures)
                } else {
                    Ok(())
                }
            }
        }
        .map_err(Error::Validation)
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
