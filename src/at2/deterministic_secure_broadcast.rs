/// An implementation of deterministic SecureBroadcast.
use std::collections::{HashMap, HashSet};

use crate::at2::bank::{Bank, Money, Transfer};
use crate::at2::identity::{Identity, Sig};

use bincode;
use crdts::{CmRDT, Dot, VClock};
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use serde::Serialize;
use sha2::Sha512;

#[derive(Debug)]
pub struct SecureBroadcastProc {
    keypair: Keypair,
    bank: Bank,
    peers: HashSet<Identity>,
    delivered: VClock<Identity>,
    received: VClock<Identity>,
    msgs_waiting_for_signatures: HashMap<Msg, HashMap<Identity, Sig>>,
}

#[derive(Debug, Clone, Serialize)]
pub enum Payload {
    RequestValidation {
        msg: Msg,
    },
    SignedValidated {
        msg: Msg,
        sig: Sig,
    },
    ProofOfAgreement {
        msg: Msg,
        proof: HashMap<Identity, Sig>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Hash)]
pub struct Msg {
    op: Transfer,
    dot: Dot<Identity>,
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub source: Identity,
    pub dest: Identity,
    pub payload: Payload,
    pub sig: Sig,
}

impl SecureBroadcastProc {
    pub fn new() -> Self {
        let mut csprng = OsRng::new().unwrap();
        let keypair = Keypair::generate::<Sha512, _>(&mut csprng);
        let identity = Identity(keypair.public);
        Self {
            keypair: keypair,
            bank: Bank::new(identity),
            peers: HashSet::new(),
            delivered: VClock::new(),
            received: VClock::new(),
            msgs_waiting_for_signatures: HashMap::new(),
        }
    }

    pub fn update_peer_list(&mut self, peers_with_balances: &HashMap<Identity, Money>) {
        for (peer, balance) in peers_with_balances.iter() {
            self.bank.onboard_identity(*peer, *balance);
            self.peers.insert(*peer);
        }
    }

    pub fn identity(&self) -> Identity {
        Identity(self.keypair.public)
    }

    pub fn exec_bft_op(&self, f: impl FnOnce(&Bank) -> Option<Transfer>) -> Vec<Packet> {
        if let Some(op) = f(&self.bank) {
            println!("[DSB] bft op created, broadcasting request for validation");

            let validation_request = Payload::RequestValidation {
                msg: Msg {
                    op,
                    dot: self.received.inc(self.identity()),
                },
            };
            self.broadcast(validation_request)
        } else {
            println!("[DSB] bft op did not produce a message");
            vec![]
        }
    }

    pub fn read_state<V>(&self, f: impl FnOnce(&Bank) -> V) -> V {
        f(&self.bank)
    }

    pub fn handle_packet(&mut self, packet: Packet) -> Vec<Packet> {
        println!(
            "[DSB] {} handling packet from {}",
            self.identity(),
            packet.source
        );
        if self.verify_sig(&packet.source, &packet.payload, &packet.sig)
            && self.validate_payload(packet.source, &packet.payload)
        {
            match packet.payload {
                Payload::RequestValidation { msg } => {
                    self.received.apply(msg.dot);

                    let msg_sig = self.sign(&msg);
                    let validation = Payload::SignedValidated { msg, sig: msg_sig };
                    vec![self.send(packet.source, validation)]
                }
                Payload::SignedValidated { msg, sig } => {
                    self.msgs_waiting_for_signatures
                        .entry(msg.clone())
                        .or_default()
                        .insert(packet.source, sig);

                    let num_signatures = self.msgs_waiting_for_signatures[&msg].len();

                    if self.quorum(num_signatures) {
                        // We have quorum, broadcast proof of agreement to network
                        let proof = self.msgs_waiting_for_signatures[&msg].clone();
                        self.broadcast(Payload::ProofOfAgreement { msg: msg, proof })
                    } else {
                        vec![]
                    }
                }
                Payload::ProofOfAgreement { msg, .. } => {
                    self.delivered.apply(msg.dot);
                    self.bank.apply(msg.op);
                    vec![] // TODO: we must put in an ack here so that the source knows that honest procs have applied the transaction
                }
            }
        } else {
            println!("[ERROR] Failed to verify message, dropping {:?}", packet);
            vec![]
        }
    }

    fn validate_payload(&self, from: Identity, payload: &Payload) -> bool {
        let validation_tests = match payload {
            Payload::RequestValidation { msg } => vec![
                (from == msg.dot.actor, "source does not match the msg dot"),
                (msg.dot == self.received.inc(from), "not the next msg"),
                (self.bank.validate(from, &msg.op), "failed bank validation"),
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
            .map(|(_test, msg)| println!("[INVALID] {}", msg))
            .is_none()
    }

    fn quorum(&self, n: usize) -> bool {
        n * 3 >= self.peers.len() * 2
    }

    fn broadcast(&self, msg: Payload) -> Vec<Packet> {
        println!("[DSB] broadcasting {}->{:?}", self.identity(), self.peers);
        self.peers
            .iter()
            .map(|dest_p| self.send(*dest_p, msg.clone()))
            .collect()
    }

    fn send(&self, dest: Identity, payload: Payload) -> Packet {
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
