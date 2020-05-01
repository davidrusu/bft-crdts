use crate::at2::identity::Identity;
use crate::at2::traits::SecureBroadcastAlgorithm;

use serde::Serialize;

use std::collections::HashSet;
use std::hash::Hash;

#[derive(Debug, Clone)]
struct CausalSet<M: Hash> {
    id: Identity,
    members: HashSet<M>,
}

#[derive(Debug, Clone, Serialize, Hash, PartialEq, Eq)]
enum Op<M> {
    Add(M),
    Rm(M),
}

impl<M: Hash + Eq> CausalSet<M> {
    pub fn add(&self, member: M) -> Option<Op<M>> {
        if self.members.contains(&member) {
            None
        } else {
            Some(Op::Add(member))
        }
    }

    pub fn rm(&self, member: M) -> Option<Op<M>> {
        if self.members.contains(&member) {
            Some(Op::Rm(member))
        } else {
            None
        }
    }
}

impl<M: Hash + Clone + Eq + std::fmt::Debug + Serialize> SecureBroadcastAlgorithm for CausalSet<M> {
    type Op = Op<M>;

    fn new(id: Identity) -> Self {
        Self {
            id,
            members: Default::default(),
        }
    }

    fn sync_from(&mut self, other: Self) {
        self.members.extend(other.members);
    }

    /// Protection against Byzantines
    fn validate(&self, _from: &Identity, op: &Self::Op) -> bool {
        match op {
            Op::Add(_member) => true,
            Op::Rm(member) => self.members.contains(member),
        }
    }

    /// Executed once an op has been validated
    fn apply(&mut self, op: Self::Op) {
        match op {
            Op::Add(member) => {
                self.members.insert(member);
            }
            Op::Rm(member) => {
                self.members.remove(&member);
            }
        }
    }
}
