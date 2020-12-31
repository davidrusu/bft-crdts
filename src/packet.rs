use serde::{Deserialize, Serialize};
use crdts::VClock;

use crate::actor::{Actor, Sig};
use crate::bft_membership;
use crate::deterministic_secure_broadcast;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Packet<Op> {
    pub source: Actor,
    pub dest: Actor,
    pub payload: Payload<Op>,
    pub sig: Sig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Payload<AlgoOp> {
    AntiEntropy {
	delivered: VClock<Actor>,
	generation: bft_membership::Generation,
    },
    SecureBroadcast(deterministic_secure_broadcast::Op<AlgoOp>),
    Membership(bft_membership::Vote),
}
