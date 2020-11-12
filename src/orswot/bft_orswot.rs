use crdts::{orswot, CmRDT, CvRDT, VClock};

use crate::actor::Actor;
use crate::traits::SecureBroadcastAlgorithm;

use serde::Serialize;

// Todo: add closure for app to perform biz logic validation.

#[derive(Debug, Serialize, PartialEq, Eq, Clone)]
pub struct BFTOrswot<M: Clone + Eq + std::hash::Hash + std::fmt::Debug + Serialize> {
    actor: Actor,
    orswot: orswot::Orswot<M, Actor>,
    received: VClock<Actor>,
}

impl<M: Clone + Eq + std::hash::Hash + std::fmt::Debug + Serialize> BFTOrswot<M> {
    pub fn add(&self, member: M) -> orswot::Op<M, Actor> {
        let add_ctx = self.orswot.read_ctx().derive_add_ctx(self.actor);
        self.orswot.add(member, add_ctx)
    }

    pub fn rm(&self, member: M) -> Option<orswot::Op<M, Actor>> {
        let contains_ctx = self.orswot.contains(&member);
        if contains_ctx.val {
            Some(self.orswot.rm(member, contains_ctx.derive_rm_ctx()))
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

impl<M: Clone + Eq + std::hash::Hash + std::fmt::Debug + Serialize> SecureBroadcastAlgorithm
    for BFTOrswot<M>
{
    type Op = orswot::Op<M, Actor>;
    type ReplicatedState = orswot::Orswot<M, Actor>;

    fn new(actor: Actor) -> Self {
        BFTOrswot {
            actor,
            orswot: orswot::Orswot::new(),
            received: VClock::new(),
        }
    }

    fn state(&self) -> Self::ReplicatedState {
        self.orswot.clone()
    }

    fn sync_from(&mut self, other: Self::ReplicatedState) {
        self.received.merge(other.clock());
        self.orswot.merge(other);
    }

    fn validate(&mut self, from: &Actor, op: &Self::Op) -> bool {
        match op {
            orswot::Op::Add { dot, members: _ } => {
                if &dot.actor != from {
                    println!(
                        "[ORSWOT/INVALID] Attempting to add with a dot different from the source proc"
                    );
                    false
                } else if dot != &self.received.inc(*from) {
                    println!("[ORSWOT/INVALID] Dot is not a direct successor");
                    false
                } else {
                    self.received.apply(dot.clone());
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

    fn apply(&mut self, op: Self::Op) {
        match &op {
            orswot::Op::Add { dot, .. } => self.received.apply(dot.clone()),
            _ => (),
        }
        self.orswot.apply(op);
    }
}
