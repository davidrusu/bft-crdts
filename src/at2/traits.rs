use crate::at2::identity::Identity;

use serde::Serialize;

pub trait SecureBroadcastAlgorithm: Clone + std::fmt::Debug {
    type Op: Serialize + Clone + std::fmt::Debug + std::hash::Hash + std::cmp::Eq;

    /// initialize a new replica of this algorithm
    fn new(id: Identity) -> Self;

    /// Called when onboarding a new replica of this algorithm
    fn sync_from(&mut self, other: Self);

    /// Protection against Byzantines
    fn validate(&self, from: &Identity, op: &Self::Op) -> bool;

    /// Executed once an op has been validated
    fn apply(&mut self, op: Self::Op);
}
