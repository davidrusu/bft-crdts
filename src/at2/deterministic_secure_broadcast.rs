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
pub enum SecureBroadcastPayload {
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
    pub payload: SecureBroadcastPayload,
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

            let validation_request = SecureBroadcastPayload::RequestValidation {
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
        if self.verify_source(packet.source, &packet.payload, &packet.sig) {
            match packet.payload {
                SecureBroadcastPayload::RequestValidation { msg } => {
                    if self.validate_msg(packet.source, &msg) {
                        self.received.apply(msg.dot);

                        let msg_sig = self.sign(&msg);
                        let validation =
                            SecureBroadcastPayload::SignedValidated { msg, sig: msg_sig };

                        let packet_sig = self.sign(&validation);
                        vec![Packet {
                            source: self.identity(),
                            dest: packet.source,
                            payload: validation,
                            sig: packet_sig,
                        }]
                    } else {
                        println!("[DSB] Dropping invalid msg {:?}", msg);
                        vec![]
                    }
                }
                SecureBroadcastPayload::SignedValidated { msg, sig } => {
                    // Ensure we are actually the source of this msg.
                    // assert_eq!(msg.dot.actor, self.keypair.public);
                    if self.verify_source(packet.source, &msg, &sig) {
                        self.msgs_waiting_for_signatures
                            .entry(msg.clone())
                            .or_default()
                            .insert(packet.source, sig);

                        let num_signatures = self
                            .msgs_waiting_for_signatures
                            .get(&msg)
                            .map(|sigs| sigs.len())
                            .unwrap(); // we just inserted this sig so we should have at least 1

                        if self.quorum(num_signatures) {
                            let proof = self
                                .msgs_waiting_for_signatures
                                .get(&msg)
                                .cloned()
                                .unwrap_or_default();

                            // We have quorum, broadcast proof of agreement to network
                            self.broadcast(SecureBroadcastPayload::ProofOfAgreement {
                                msg: msg,
                                proof,
                            })
                        } else {
                            // We don't yet have quorum, wait for more signatures
                            vec![]
                        }
                    } else {
                        println!("[DSB] Invalid signature on validation");
                        vec![]
                    }
                }
                SecureBroadcastPayload::ProofOfAgreement { msg, proof } => {
                    if self.delivered.inc(packet.source) == msg.dot {
                        assert!(self.quorum(proof.len()));

                        for (proof_source, sig) in proof {
                            assert!(self.peers.contains(&proof_source));
                            assert!(self.verify_source(proof_source, &msg, &sig));
                        }

                        self.delivered.apply(msg.dot);
                        self.bank.apply(msg.op);
                        vec![]
                    } else {
                        println!("[DSB] Dropping out of order packer from {}", packet.source);
                        vec![]
                    }
                }
            }
        } else {
            println!("[ERROR] Failed to verify message, dropping {:?}", packet);
            vec![]
        }
    }

    fn broadcast(&self, msg: SecureBroadcastMsg) -> Vec<Packet> {

    fn validate_msg(&self, from: Identity, msg: &Msg) -> bool {
        if from != msg.dot.actor {
            println!(
                "[INVALID] Transfer from {:?} does not match the msg source version {:?}",
                from, msg.dot
            );
            false
        } else if msg.dot != self.received.inc(from) {
            println!(
                "[INVALID] {} Source version {:?} is not a direct successor of last transfer from {}: {:?}",
                self.identity(), msg.dot, from, self.received.dot(from)
            );
            false
        } else {
            // Finally, check with the underlying algorithm
            self.bank.validate(from, &msg.op)
        }
    }

    fn quorum(&self, n: usize) -> bool {
        n * 3 >= self.peers.len() * 2
    }

    fn broadcast(&self, msg: SecureBroadcastPayload) -> Vec<Packet> {
        println!("[DSB] broadcasting {}->{:?}", self.identity(), self.peers);
        self.peers
            .iter()
            .map(|dest_p| self.send(*dest_p, msg.clone()))
            .collect()
    }

    fn send(&self, dest: Identity, payload: SecureBroadcastPayload) -> Packet {
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

    fn verify_source(&self, source: Identity, msg: impl Serialize, sig: &Sig) -> bool {
        let msg_bytes = bincode::serialize(&msg).expect("Failed to serialize");
        source.0.verify::<Sha512>(&msg_bytes, &sig.0).is_ok()
    }
}
