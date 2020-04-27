/// An implementation of deterministic SecureBroadcast.
use std::collections::{HashMap, HashSet};

use crate::at2::identity::{Identity, Sig};
use crate::at2::traits::SecureBroadcastAlgorithm;

use bincode;
use crdts::{CmRDT, CvRDT, Dot, VClock};
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use serde::Serialize;
use sha2::Sha512;

#[derive(Debug)]
pub struct SecureBroadcastProc<A: SecureBroadcastAlgorithm> {
    keypair: Keypair,
    algo: A,
    peers: HashSet<Identity>,
    delivered: VClock<Identity>,
    received: VClock<Identity>,
    msgs_waiting_for_signatures: HashMap<Msg<A::Op>, HashMap<Identity, Sig>>,
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
    op: Op,
    dot: Dot<Identity>,
}

impl<A: SecureBroadcastAlgorithm> SecureBroadcastProc<A> {
    pub fn new() -> Self {
        let mut csprng = OsRng::new().unwrap();
        let keypair = Keypair::generate::<Sha512, _>(&mut csprng);
        let identity = Identity(keypair.public);
        Self {
            keypair: keypair,
            algo: A::new(identity),
            peers: vec![identity].into_iter().collect(),
            delivered: VClock::new(),
            received: VClock::new(),
            msgs_waiting_for_signatures: HashMap::new(),
        }
    }

    pub fn add_peer(&mut self, peer: Identity) {
        // TODO: we probably want BFT agreement on adding a new peer
        self.peers.insert(peer);
    }

    pub fn sync_from(&mut self, other: &Self) {
        // TODO: this is not ideal, we dont want to ship the entire local state over
        // ie. keypair, msgs_waiting_for_signatures, etc..

        self.peers.extend(other.peers.clone());
        self.delivered.merge(other.delivered.clone());
        self.received.merge(other.received.clone());
        self.algo.sync_from(other.algo.clone());
    }

    pub fn identity(&self) -> Identity {
        Identity(self.keypair.public)
    }

    pub fn exec_bft_op(&self, f: impl FnOnce(&A) -> Option<A::Op>) -> Vec<Packet<A::Op>> {
        if let Some(op) = f(&self.algo) {
            let msg = Msg {
                op,
                dot: self.received.inc(self.identity()),
            };
            println!("[DSB] {} initiating bft for msg {:?}", self.identity(), msg);
            let validation_request = Payload::RequestValidation { msg: msg };
            self.broadcast(validation_request)
        } else {
            println!("[DSB] bft op did not produce a message");
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

                let msg_sig = self.sign(&msg);
                let validation = Payload::SignedValidated { msg, sig: msg_sig };
                vec![self.send(packet.source, validation)]
            }
            Payload::SignedValidated { msg, sig } => {
                println!("[DSB] signed validated");
                self.msgs_waiting_for_signatures
                    .entry(msg.clone())
                    .or_default()
                    .insert(packet.source, sig);

                let num_signatures = self.msgs_waiting_for_signatures[&msg].len();

                if self.quorum(num_signatures) {
                    println!("[DSB] we have quorum over msg, sending proof to network");
                    // We have quorum, broadcast proof of agreement to network
                    let proof = self.msgs_waiting_for_signatures[&msg].clone();
                    self.broadcast(Payload::ProofOfAgreement { msg: msg, proof })
                } else {
                    vec![]
                }
            }
            Payload::ProofOfAgreement { msg, .. } => {
                println!("[DSB] proof of agreement");
                self.delivered.apply(msg.dot);
                self.algo.apply(msg.op);
                vec![] // TODO: we must put in an ack here so that the source knows that honest procs have applied the transaction
            }
        }
    }

    fn validate_payload(&self, from: Identity, payload: &Payload<A::Op>) -> bool {
        let validation_tests = match payload {
            Payload::RequestValidation { msg } => vec![
                (from == msg.dot.actor, "source does not match the msg dot"),
                (msg.dot == self.received.inc(from), "not the next msg"),
                (self.algo.validate(&from, &msg.op), "failed bank validation"),
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

    fn quorum(&self, n: usize) -> bool {
        // To simplify things temporarily, we set quorum to be the entire network.
        // n * 3 >= self.peers.len() * 2

        n >= self.peers.len()
    }

    fn broadcast(&self, msg: Payload<A::Op>) -> Vec<Packet<A::Op>> {
        println!("[DSB] broadcasting {}->{:?}", self.identity(), self.peers);
        self.peers
            .iter()
            .map(|dest_p| self.send(*dest_p, msg.clone()))
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

    fn sign(&self, msg: impl Serialize) -> Sig {
        let msg_bytes = bincode::serialize(&msg).expect("Failed to serialize");
        let msg_sig = self.keypair.sign::<Sha512>(&msg_bytes);

        Sig(msg_sig)
    }

    fn verify_sig(&self, source: &Identity, msg: impl Serialize, sig: &Sig) -> bool {
        let msg_bytes = bincode::serialize(&msg).expect("Failed to serialize");
        source.0.verify::<Sha512>(&msg_bytes, &sig.0).is_ok()
    }
}
