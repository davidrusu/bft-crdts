use std::fmt::Debug;
use std::hash::Hash;

use serde::Serialize;

use crate::actor::Actor;

pub trait SecureBroadcastAlgorithm: Clone + Debug + Eq {
    type Op: Debug + Clone + Hash + Eq + Serialize;
    type ReplicatedState: Clone + Debug + Eq;

    /// initialize a new replica of this algorithm
    fn new(actor: Actor) -> Self;

    fn state(&self) -> Self::ReplicatedState;

    /// Called when onboarding a new replica of this algorithm
    fn sync_from(&mut self, other: Self::ReplicatedState);

    /// callback from Secure Broadcast once a message has been agreed upon by the network.
    fn deliver(&mut self, from: Actor, op: Self::Op);
}
