/// Implementation of https://arxiv.org/pdf/1812.10844.pdf
///
/// Deviations from AT2 as defined in the paper
/// 1.  DONE: we decompose dependency tracking from the distributed algorithm
/// 3.  TODO: we genaralize over the distributed algorithm
/// 4.  TODO: seperate out resources from identity (a process id both identified an agent and an account) we generalize this so that
use std::collections::HashSet;

use crdts::{CmRDT, Dot, VClock};
use serde::Serialize;

use crate::at2::bank::{Bank, Money, Transfer};
use crate::at2::identity::Identity;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Hash)]
pub struct Msg {
    op: Transfer,
    pub source_version: Dot<Identity>, // Consider moving this into the DSP layer
}

#[derive(Debug)]
pub struct Proc {
    // The name this process goes by
    id: Identity,

    // The global bank we are keeping in sync across all procs in the network
    bank: Bank,

    // Applied versions
    seq: VClock<Identity>,

    // Set of delivered (but not validated) transfers
    to_validate: Vec<(Identity, Msg)>,

    // Operations that are causally related to the next operation on a given account
    peers: HashSet<Identity>,
}

impl Proc {
    pub fn new(id: Identity) -> Self {
        Proc {
            id,
            bank: Bank::new(id),
            seq: VClock::new(),
            to_validate: Vec::new(),
            peers: HashSet::new(),
        }
    }

    pub fn onboard_identity(&mut self, identity: Identity, initial_balance: Money) {
        self.bank.onboard_identity(identity, initial_balance);
    }

    pub fn transfer(&self, from: Identity, to: Identity, amount: Money) -> Option<Msg> {
        self.bank.transfer(from, to, amount).map(|transfer_op| Msg {
            op: transfer_op,
            source_version: self.seq.inc(from),
        })
    }

    pub fn balance(&self, identity: Identity) -> Money {
        self.bank.balance(identity)
    }

    /// Executed when a transfer from `from` becomes valid.
    pub fn on_validated(&mut self, from: Identity, msg: Msg) {
        assert!(self.validate(from, &msg));
        assert_eq!(msg.source_version, self.seq.inc(from));

        // TODO: rename Proc::seq to Proc::knowledge ala. VVwE
        // TODO: rename Proc::rec to Proc::forward_knowledge ala. VVwE
        // TODO: add test that "forward_knowleged >= knowledge" is invariant
        self.seq.apply(msg.source_version);

        // Finally, apply the operation to the underlying algorithm
        self.bank.apply(msg.op);
    }

    pub fn validate(&self, from: Identity, msg: &Msg) -> bool {
        if from != msg.source_version.actor {
            println!(
                "[INVALID] Transfer from {:?} does not match the msg source version {:?}",
                from, msg.source_version
            );
            false
        } else if msg.source_version != self.seq.inc(from) {
            println!(
                "[INVALID] {} Source version {:?} is not a direct successor of last transfer from {}: {:?}",
                self.id, msg.source_version, from, self.seq.dot(from)
            );
            false
        } else {
            // Finally, check with the underlying algorithm
            self.bank.validate(from, &msg.op)
        }
    }
}
