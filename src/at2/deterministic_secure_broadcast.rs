/// An implementation of deterministic SecureBroadcast.
use std::collections::{HashMap, HashSet};

use crate::at2::bank::Money;
use crate::at2::identity::Identity;
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
    msgs_waiting_for_signatures: HashMap<Msg, HashMap<Identity, Signature>>,
}

#[derive(Debug, Clone, Serialize)]
pub enum SecureBroadcastMsg {
    RequestValidation {
        msg: Msg,
    },
    SignedValidated {
        msg: Msg,
        sig: Signature,
    },
    ProofOfAgreement {
        msg: Msg,
        proof: HashMap<Identity, Signature>,
    },
}

#[derive(Debug, Clone)]
pub struct SignedEnvelope {
    dest: Identity,
    msg: SecureBroadcastMsg,
    sig: Signature,
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
        }
    }

    pub fn identity(&self) -> Identity {
        Identity(self.keypair.public)
    }

    pub fn exec(&mut self, f: impl FnOnce(&Proc) -> Option<Msg>) -> Vec<SignedEnvelope> {
        if let Some(msg) = f(&self.proc) {
            let validation_request = SecureBroadcastMsg::RequestValidation { msg: msg.clone() };

            // Sanity check, ensure we are not already waiting on this msg
            assert!(!self.msgs_waiting_for_signatures.contains_key(&msg));
            // TODO: do we need to initialize this?
            // self.msgs_waiting_for_signatures.insert(msg, ::new()); // should include own signature here

            // TODO: make sure peers contains self proc id
            self.broadcast(validation_request)
        } else {
            vec![]
        }
    }

    pub fn read_state<V>(&self, f: impl FnOnce(&Proc) -> V) -> V {
        f(&self.proc)
    }

    pub fn handle_msg(
        &mut self,
        source: Identity,
        signed_broadcast_msg: SignedEnvelope,
    ) -> Vec<SignedEnvelope> {
        if self.verify_source(source, &signed_broadcast_msg.msg, signed_broadcast_msg.sig) {
            match signed_broadcast_msg.msg {
                SecureBroadcastMsg::RequestValidation { msg } => {
                    if self.proc.validate(source, &msg) {
                        let msg_sig = self.sign(&msg);
                        let validation_msg =
                            SecureBroadcastMsg::SignedValidated { msg, sig: msg_sig };

                        let envelope_sig = self.sign(&validation_msg);
                        vec![SignedEnvelope {
                            dest: source,
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
                    assert!(self.msgs_waiting_for_signatures.contains_key(&msg));

                    if self.verify_source(source, &msg, sig) {
                        self.msgs_waiting_for_signatures
                            .entry(msg.clone())
                            .or_default()
                            .insert(source, sig);

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

                    for (source, sig) in proof {
                        assert!(self.peers.contains(&source));
                        assert!(self.verify_source(source, &msg, sig));
                    }

                    self.proc.on_validated(source, msg);
                    vec![]
                }
            }
        } else {
            println!(
                "[ERROR] Failed to verify message, dropping {:?} from {:?}",
                signed_broadcast_msg, source
            );
            vec![]
        }
    }

    fn broadcast(&self, msg: SecureBroadcastMsg) -> Vec<SignedEnvelope> {
        self.peers
            .iter()
            .map(|dest_p| self.send(*dest_p, msg.clone()))
            .collect()
    }

    fn send(&self, dest: Identity, msg: SecureBroadcastMsg) -> SignedEnvelope {
        let sig = self.sign(&msg);
        SignedEnvelope { dest, msg, sig }
    }

    // fn sign(&self, secure_broadcast_msg: &SecureBroadcastMsg) -> Signature {
    //     let msg_bytes = bincode::serialize(&secure_broadcast_msg).expect("Failed to serialize");
    //     let msg_sig = self.keypair.sign(&msg_bytes);
    //
    //     msg_sig
    // }

    fn sign(&self, msg: impl Serialize) -> Signature {
        let msg_bytes = bincode::serialize(&msg).expect("Failed to serialize");
        let msg_sig = self.keypair.sign::<Sha512>(&msg_bytes);

        msg_sig
    }

    // fn verify_source(&self, source: PublicKey, msg: &SecureBroadcastMsg, sig: Signature) -> bool {
    //     let msg_bytes = bincode::serialize(&msg).expect("Failed to serialize");
    //     source.verify(&msg_bytes, &sig).is_ok()
    // }

    fn verify_source(&self, source: Identity, msg: impl Serialize, sig: Signature) -> bool {
        let msg_bytes = bincode::serialize(&msg).expect("Failed to serialize");
        source.0.verify::<Sha512>(&msg_bytes, &sig).is_ok()
    }
}
