/// Implementation of https://arxiv.org/pdf/1812.10844.pdf
///
/// Deviations from AT2 as defined in the paper
/// 1.  DONE: we decompose dependency tracking from the distributed algorithm
/// 3.  TODO: we genaralize over the distributed algorithm
/// 4.  TODO: seperate out resources from identity (a process id both identified an agent and an account) we generalize this so that
use std::collections::HashSet;
use std::mem;

use crdts::{CmRDT, Dot, VClock};
use serde::Serialize;

use crate::at2::bank::{Account, Bank, Money, Transfer};
use crate::at2::identity::Identity;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Hash)]
pub struct Msg {
    op: Transfer,
    source_version: Dot<Identity>,
}

#[derive(Debug)]
pub struct Proc {
    // The name this process goes by
    id: Identity,

    // The global bank we are keeping in sync across all procs in the network
    bank: Bank,

    // Applied versions
    seq: VClock<Identity>,

    // Received but not necessarily applied versions
    rec: VClock<Identity>,

    // Set of delivered (but not validated) transfers
    to_validate: Vec<(Identity, Msg)>,

    // Operations that are causally related to the next operation on a given account
    peers: HashSet<Identity>,
}

impl Proc {
    pub fn new(id: Identity, initial_balance: Money) -> Self {
        let mut proc = Proc {
            id,
            bank: Bank::new(id),
            seq: VClock::new(),
            rec: VClock::new(),
            to_validate: Vec::new(),
            peers: HashSet::new(),
        };

        proc.bank.onboard_account(id, initial_balance);

        proc
    }

    pub fn transfer(&self, from: Identity, to: Identity, amount: Money) -> Option<Msg> {
        assert_eq!(from, self.id);
        self.bank.transfer(from, to, amount).map(|transfer_op| Msg {
            op: transfer_op,
            source_version: self.seq.inc(from),
        })
    }

    pub fn read(&self, account: Account) -> Money {
        self.bank.read(account)
    }

    /// Executed when we successfully deliver messages to process p
    pub fn on_delivery(&mut self, from: Identity, msg: Msg) {
        // TODO: this is no longer being executed
        assert_eq!(from, msg.source_version.actor);

        // Secure broadcast callback
        if msg.source_version == self.rec.inc(from) {
            println!(
                "{:?} Accepted message from {:?} and enqueued for validation",
                self.id, from
            );
            self.rec.apply(msg.source_version);
            self.to_validate.push((from, msg));
        } else {
            println!(
                "{:?} Rejected message from {:?}, transfer source version is invalid: {:?}",
                self.id, from, msg.source_version
            );
        }
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
                "[INVALID] Source version {:?} is not a direct successor of last transfer from {:?}: {:?}",
                msg.source_version, from, self.seq.dot(from)
            );
            false
        } else {
            // Finally, check with the underlying algorithm
            self.bank.validate(from, &msg.op)
        }
    }

    pub fn handle_msg(&mut self, from: Identity, msg: Msg) {
        self.on_delivery(from, msg);
        self.process_msg_queue();
    }

    pub fn process_msg_queue(&mut self) {
        let to_validate = mem::replace(&mut self.to_validate, Vec::new());
        for (to, msg) in to_validate {
            if self.validate(to, &msg) {
                self.on_validated(to, msg);
            } else {
                println!("[DROP] invalid message detected {:?}", (to, msg));
            }
        }
    }
}
