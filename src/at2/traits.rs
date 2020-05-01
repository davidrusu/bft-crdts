use crate::at2::identity::Identity;

use serde::Serialize;

pub trait SecureBroadcastAlgorithm: Clone + std::fmt::Debug + Eq {
    type Op: std::fmt::Debug + Clone + std::hash::Hash + std::cmp::Eq + Serialize;
    type ReplicatedState: Clone + std::fmt::Debug + Eq;

    /// initialize a new replica of this algorithm
    fn new(id: Identity) -> Self;

    fn state(&self) -> Self::ReplicatedState;

    /// Called when onboarding a new replica of this algorithm
    fn sync_from(&mut self, other: Self::ReplicatedState);

    /// Protection against Byzantines
    fn validate(&self, from: &Identity, op: &Self::Op) -> bool;

    /// Executed once an op has been validated
    fn apply(&mut self, op: Self::Op);
}
