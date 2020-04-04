use std::collections::HashSet;

use crdts::Actor;

pub trait DistributedCausalAlgorithm: Default {
    type Identity: Actor;
    type Ref;
    type State;
    type Op: DistributedCausalOp<Ref = Self::Ref>;

    /// Initialize a new resource
    fn create_resource(&mut self, resource_id: Self::Ref, initial_state: Self::State);

    /// I don't feel this is needed
    fn initial_state(&self, resource_id: &Self::Ref) -> Self::State;

    /// Read the current state of a resource
    fn read(&self, resource_id: Self::Ref) -> Self::State;

    /// Protection against the Byzantines
    fn validate(&self, source: Self::Identity, op: &Self::Op) -> bool;

    /// Once an op is validated, this method will be called an the Op will be considered applied
    fn apply(&mut self, op: Self::Op);
}

pub trait DistributedCausalOp {
    type Ref;

    /// In order to build the causal graph, we need to know which resources are
    /// affected by a given operation in order to build the causal graph.
    fn affected_resources(&self) -> HashSet<Self::Ref>;
}
