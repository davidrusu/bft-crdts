use std::fmt::Debug;
use std::hash::Hash;

use crdts::{orswot, CmRDT, CvRDT, Dot, VClock};

use crate::actor::Actor;
use crate::traits::SecureBroadcastAlgorithm;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BFTOp<M: Clone + Eq + Hash + Debug + Serialize> {
    pub op: orswot::Op<M, Actor>,
    pub seq_num: u64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct BFTOrswot<M: Clone + Eq + Hash + Debug + Serialize> {
    pub actor: Actor,
    pub orswot: orswot::Orswot<M, Actor>,
    pub seq: VClock<Actor>,
    pub invalid_packets: u64,
}

impl<M: Clone + Eq + Hash + Debug + Serialize> BFTOrswot<M> {
    fn validate(&self, from: &Actor, bft_op: &BFTOp<M>) -> bool {
        let BFTOp { op, seq_num } = bft_op;
        if *seq_num != self.seq.get(from) + 1 {
            println!("[ORSWOT/INVALID] op seq num is not a direct successor of the previous op from this source");
            return false;
        }
        match op {
            orswot::Op::Add { dot, members: _ } => {
                if &dot.actor != from {
                    println!(
                        "[ORSWOT/INVALID] Attempting to add with a dot different from the source proc"
                    );
                    false
                } else {
                    true
                }
            }
            orswot::Op::Rm { clock, members } => {
                if members.len() != 1 {
                    println!("[ORSWOT/INVALID] We only support removes of a single element");
                    false
                } else if !(clock <= &self.orswot.clock()) {
                    // NOTE: this check renders all the "deferred_remove" logic in the ORSWOT obsolete.
                    //       The deferred removes would buffer these out-of-order removes.
                    println!("[ORSWOT/INVALID] This rm op is removing data we have not yet seen");
                    false
                } else {
                    true
                }
            }
        }
    }

    pub fn add(&self, member: M) -> BFTOp<M> {
        let add_ctx = self.orswot.read_ctx().derive_add_ctx(self.actor);
        BFTOp {
            op: self.orswot.add(member, add_ctx),
            seq_num: self.seq.get(&self.actor) + 1,
        }
    }

    pub fn rm(&self, member: M) -> Option<BFTOp<M>> {
        let contains_ctx = self.orswot.contains(&member);
        if contains_ctx.val {
            Some(BFTOp {
                op: self.orswot.rm(member, contains_ctx.derive_rm_ctx()),
                seq_num: self.seq.get(&self.actor) + 1,
            })
        } else {
            None
        }
    }

    pub fn actor(&self) -> &Actor {
        &self.actor
    }

    pub fn orswot(&self) -> &orswot::Orswot<M, Actor> {
        &self.orswot
    }
}

impl<M: Clone + Eq + Hash + Debug + Serialize> SecureBroadcastAlgorithm for BFTOrswot<M> {
    type Op = BFTOp<M>;
    type ReplicatedState = orswot::Orswot<M, Actor>;

    fn new(actor: Actor) -> Self {
        BFTOrswot {
            actor,
            orswot: orswot::Orswot::new(),
            seq: VClock::new(),
            invalid_packets: 0,
        }
    }

    fn state(&self) -> Self::ReplicatedState {
        self.orswot.clone()
    }

    fn sync_from(&mut self, other: Self::ReplicatedState) {
        self.orswot.merge(other);
    }

    fn deliver(&mut self, from: Actor, bft_op: Self::Op) {
        if self.validate(&from, &bft_op) {
            let BFTOp { op, seq_num } = bft_op;
            self.seq.apply(Dot {
                actor: from,
                counter: seq_num,
            });
            self.orswot.apply(op);
        } else {
            self.invalid_packets += 1;
            println!(
                "[BFT_ORSWOT] dropping invalid op from source: {:?} op: {:?}",
                from, bft_op
            );
        }
    }
}
