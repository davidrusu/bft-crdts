/// An implementation of deterministic SecureBroadcast.
use std::collections::{HashMap, HashSet};

use crate::at2::bank::Money;
use crate::at2::identity::{Identity, Sig};
use crate::at2::proc::{Msg, Proc};

use bincode;
use ed25519_dalek::{Keypair, Signature};
use rand::rngs::OsRng;
use serde::Serialize;
use sha2::Sha512;

#[derive(Debug)]
pub struct SecureBroadcastProc {
    keypair: Keypair,
    proc: Proc,
    peers: HashSet<Identity>,
    // delivered: VClock<Identity>,
    // received: VClock<Identity>, // TODO
    // to_validate: Vec<(Identity, Msg)>,
    msgs_waiting_for_signatures: HashMap<Msg, HashMap<Identity, Sig>>,
}

#[derive(Debug, Clone, Serialize)]
pub enum SecureBroadcastMsg {
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

#[derive(Debug, Clone)]
pub struct Packet {
    pub source: Identity,
    pub dest: Identity,
    pub msg: SecureBroadcastMsg,
    pub sig: Sig,
}

impl SecureBroadcastProc {
    pub fn new() -> Self {
        let mut csprng = OsRng::new().unwrap();
        let keypair = Keypair::generate::<Sha512, _>(&mut csprng);
        let identity = Identity(keypair.public);
        Self {
            keypair: keypair,
            proc: Proc::new(identity),
            peers: HashSet::new(),
            msgs_waiting_for_signatures: HashMap::new(),
        }
    }

    pub fn update_peer_list(&mut self, peers_with_balances: &HashMap<Identity, Money>) {
        for (peer, balance) in peers_with_balances.iter() {
            self.proc.onboard_identity(*peer, *balance);
            self.peers.insert(*peer);
        }
    }

    pub fn identity(&self) -> Identity {
        Identity(self.keypair.public)
    }

    pub fn exec_bft_op(&self, f: impl FnOnce(&Proc) -> Option<Msg>) -> Vec<Packet> {
        if let Some(msg) = f(&self.proc) {
            println!("[DSB] bft op created, broadcasting request for validation");

            let validation_request = SecureBroadcastMsg::RequestValidation { msg: msg.clone() };

            // Sanity check, ensure we are not already waiting on this msg
            assert!(!self.msgs_waiting_for_signatures.contains_key(&msg));
            self.broadcast(validation_request)
        } else {
            println!("[DSB] bft op did not produce a message");
            vec![]
        }
    }

    pub fn read_state<V>(&self, f: impl FnOnce(&Proc) -> V) -> V {
        f(&self.proc)
    }

    pub fn handle_packet(&mut self, packet: Packet) -> Vec<Packet> {
        println!("[DSB] {} handling packet {:?}", self.identity(), packet);
        if self.verify_source(packet.source, &packet.msg, packet.sig) {
            match packet.msg {
                SecureBroadcastMsg::RequestValidation { msg } => {
                    if self.proc.validate(packet.source, &msg) {
                        let msg_sig = self.sign(&msg);
                        let validation_msg =
                            SecureBroadcastMsg::SignedValidated { msg, sig: msg_sig };

                        let envelope_sig = self.sign(&validation_msg);
                        vec![Packet {
                            source: self.identity(),
                            dest: packet.source,
                            msg: validation_msg,
                            sig: envelope_sig,
                        }]
                    } else {
                        println!("[DSB] Dropping invalid msg {:?}", msg);
                        vec![]
                    }
                }
                SecureBroadcastMsg::SignedValidated { msg, sig } => {
                    // Ensure we are testing for this at a lower level
                    // assert_eq!(msg.source_version.actor, self.keypair.public);
                    if self.verify_source(packet.source, &msg, sig) {
                        self.msgs_waiting_for_signatures
                            .entry(msg.clone())
                            .or_default()
                            .insert(packet.source, sig);

                        let num_signatures = self
                            .msgs_waiting_for_signatures
                            .get(&msg)
                            .map(|sigs| sigs.len())
                            .unwrap_or(0);

                        // TODO: move this to a self.quorum() call?
                        if num_signatures * 3 >= self.peers.len() * 2 {
                            let proof = self
                                .msgs_waiting_for_signatures
                                .get(&msg)
                                .cloned()
                                .unwrap_or_default();

                            // We have >= 2/3rd quorum, broadcast proof of agreement to network
                            self.broadcast(SecureBroadcastMsg::ProofOfAgreement { msg: msg, proof })
                        } else {
                            // We don't yet have quorum, wait for more signatures
                            vec![]
                        }
                    } else {
                        println!("[DSB] Invalid signature on validation");
                        vec![]
                    }
                }
                SecureBroadcastMsg::ProofOfAgreement { msg, proof } => {
                    assert!(proof.len() * 3 >= self.peers.len() * 2);

                    for (proof_source, sig) in proof {
                        assert!(self.peers.contains(&proof_source));
                        assert!(self.verify_source(proof_source, &msg, sig));
                    }

                    self.proc.on_validated(packet.source, msg);
                    vec![]
                }
            }
        } else {
            println!("[ERROR] Failed to verify message, dropping {:?}", packet);
            vec![]
        }
    }

    fn broadcast(&self, msg: SecureBroadcastMsg) -> Vec<Packet> {
        println!("[DSB] broadcasting {}->{:?}", self.identity(), self.peers);
        self.peers
            .iter()
            .map(|dest_p| self.send(*dest_p, msg.clone()))
            .collect()
    }

    fn send(&self, dest: Identity, msg: SecureBroadcastMsg) -> Packet {
        let sig = self.sign(&msg);
        Packet {
            source: self.identity(),
            dest,
            msg,
            sig,
        }
    }

    fn sign(&self, msg: impl Serialize) -> Sig {
        let msg_bytes = bincode::serialize(&msg).expect("Failed to serialize");
        let msg_sig = self.keypair.sign::<Sha512>(&msg_bytes);

        Sig(msg_sig)
    }

    fn verify_source(&self, source: Identity, msg: impl Serialize, sig: Sig) -> bool {
        let msg_bytes = bincode::serialize(&msg).expect("Failed to serialize");
        source.0.verify::<Sha512>(&msg_bytes, &sig.0).is_ok()
    }
}
