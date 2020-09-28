use crdts::{orswot, CmRDT, CvRDT};

use crate::actor::Actor;
use crate::traits::SecureBroadcastAlgorithm;

use serde::Serialize;

#[derive(Debug, Serialize, PartialEq, Eq, Clone)]
pub struct BFTOrswot<M: Clone + Eq + std::hash::Hash + std::fmt::Debug + Serialize> {
    actor: Actor,
    orswot: orswot::Orswot<M, Actor>,
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
        }
    }

    fn state(&self) -> Self::ReplicatedState {
        self.orswot.clone()
    }

    fn sync_from(&mut self, other: Self::ReplicatedState) {
        self.orswot.merge(other);
    }

    fn validate(&self, from: &Actor, op: &Self::Op) -> bool {
        let validation_tests = match op {
            orswot::Op::Add { dot, members: _ } => vec![
                (
                    &dot.actor == from,
                    "Attempting to add with a dot different from the source proc",
                ),
                (
                    dot == &self.orswot.clock().inc(*from),
                    "Dot is not a direct successor",
                ),
            ],
            orswot::Op::Rm { clock, members } => vec![
                (
                    members.len() == 1,
                    "We only support removes of a single element",
                ),
                (
                    // NOTE: this check renders all the "deferred_remove" logic in the ORSWOT obsolete.
                    //       The deferred removes would buffer these out-of-order removes.
                    clock <= &self.orswot.clock(),
                    "This rm op is removing data we have not yet seen",
                ),
            ],
        };

        validation_tests
            .into_iter()
            .find(|(is_valid, _msg)| !is_valid)
            .map(|(_test, msg)| println!("[ORSWOT/VALIDATION] {} {:?}, {:?}", msg, op, self))
            .is_none()
    }

    fn apply(&mut self, op: Self::Op) {
        self.orswot.apply(op);
    }
}
