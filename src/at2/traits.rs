use std::fmt::Debug;
use std::hash::Hash;

use serde::Serialize;

use crate::at2::identity::Identity;

pub trait SecureBroadcastAlgorithm: Clone + Debug + Eq {
    type Op: Debug + Clone + Hash + Eq + Serialize;
    type ReplicatedState: Clone + Debug + Eq;

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
