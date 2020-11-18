use std::collections::{BTreeSet, HashMap};

use crdts::{CmRDT, Dot, VClock};
use serde::Serialize;

use crate::actor::Actor;
use crate::traits::SecureBroadcastAlgorithm;

// TODO: introduce decomp. of Account from Actor
// pub type Account = Actor; // In the paper, Actor and Account are synonymous

pub type Money = u64;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum Op {
    Transfer(Transfer), // Split out Transfer into it's own struct to get some more type safety in Bank struct
    OpenAccount { owner: Actor, balance: Money },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct Transfer {
    from: Actor,
    to: Actor,
    amount: Money,
    seq_num: u64,
    /// set of transactions that need to be applied before this transfer can be validated
    /// ie. a proof of funds
    deps: BTreeSet<Transfer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bank {
    id: Actor,
    // The set of dependencies of the next outgoing transfer
    deps: BTreeSet<Transfer>,
    rec: VClock<Actor>,
    seq: VClock<Actor>,
    // The state that is replicated and managed by the network
    replicated: BankState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BankState {
    // When a new account is created, it will be given an initial balance
    initial_balances: HashMap<Actor, Money>,

    // Set of all transfers impacting a given actor
    hist: HashMap<Actor, BTreeSet<Transfer>>, // TODO: Opening an account should be part of history
}

impl Bank {
    /// Protection against Byzantines
    fn validate(&self, from: &Actor, op: &Op) -> bool {
        let validation_tests = match op {
            Op::Transfer(transfer) => vec![
                (
                    from == &transfer.from,
                    "Sender initiated transfer on behalf of other proc",
                ),
                (transfer.seq_num == self.seq.get(&from) + 1,
                 "Transfer seq_num is not the direct successor of last transfer from the source accoutn",
                ),
                (
                    self.replicated
                        .initial_balances
                        .contains_key(&transfer.from),
                    "From account does not exist",
                ),
                (
                    self.balance(from) >= transfer.amount,
                    "Sender has insufficient funds",
                ),
                (
                    transfer.deps.is_subset(&self.history(from)),
                    "Missing dependent ops",
                ),
                // additional validation (not present in AT2 paper)
                (
                    self.replicated.initial_balances.contains_key(&transfer.to),
                    "To account does not exist",
                ),
            ],
            Op::OpenAccount { owner, balance: _ } => vec![
                (
                    from == owner,
                    "Initiator is not the owner of the new account",
                ),
                (
                    !self.replicated.initial_balances.contains_key(owner),
                    "Owner already has an account",
                ),
            ],
        };

        validation_tests
            .into_iter()
            .find(|(is_valid, _msg)| !is_valid)
            .map(|(_test, msg)| println!("[BANK/VALIDATION] {} {:?}, {:?}", msg, op, self))
            .is_none()
    }

    pub fn open_account(&self, owner: Actor, balance: Money) -> Op {
        Op::OpenAccount { owner, balance }
    }

    pub fn initial_balance(&self, actor: &Actor) -> Money {
        self.replicated
            .initial_balances
            .get(&actor)
            .cloned()
            .unwrap_or_else(|| panic!("[ERROR] No initial balance for {}", actor))
    }

    pub fn balance(&self, actor: &Actor) -> Money {
        // TODO: in the paper, when we read from an actor, we union the actor
        //       history with the deps, I don't see a use for this since anything
        //       in deps is already in the actor history. Think this through a
        //       bit more carefully.
        let h = self.history(actor);

        let outgoing: Money = h
            .iter()
            .filter(|t| &t.from == actor)
            .map(|t| t.amount)
            .sum();
        let incoming: Money = h.iter().filter(|t| &t.to == actor).map(|t| t.amount).sum();

        // We compute differences in a larger space since we need to move to signed numbers
        // and hence we lose a bit.
        let balance_delta: i128 = (incoming as i128) - (outgoing as i128);
        let balance: i128 = self.initial_balance(actor) as i128 + balance_delta;

        assert!(balance >= 0); // sanity check that we haven't violated our balance constraint
        assert!(balance <= Money::max_value() as i128); // sanity check that it's safe to downcast

        balance as Money
    }

    fn history(&self, actor: &Actor) -> BTreeSet<Transfer> {
        self.replicated
            .hist
            .get(&actor)
            .cloned()
            .unwrap_or_default()
    }

    pub fn transfer(&self, from: Actor, to: Actor, amount: Money) -> Option<Op> {
        let balance = self.balance(&from);
        // TODO: we should leave this validation to the self.validate logic, no need to duplicate it here
        if balance < amount {
            println!(
                "{} does not have enough money to transfer {} to {}. (balance: {})",
                from, amount, to, balance
            );
            None
        } else {
            let deps = self.deps.clone();
            let seq_num = self.seq.inc(self.id).counter;
            Some(Op::Transfer(Transfer {
                from,
                to,
                amount,
                seq_num,
                deps,
            }))
        }
    }
}

impl SecureBroadcastAlgorithm for Bank {
    type Op = Op;
    type ReplicatedState = BankState;

    fn new(id: Actor) -> Self {
        Bank {
            id,
            deps: Default::default(),
            replicated: BankState {
                initial_balances: Default::default(),
                hist: Default::default(),
            },
            rec: VClock::new(),
            seq: VClock::new(),
        }
    }

    fn state(&self) -> Self::ReplicatedState {
        self.replicated.clone()
    }

    fn sync_from(&mut self, other: Self::ReplicatedState) {
        for (id, balance) in other.initial_balances {
            if let Some(existing_balance) = self.replicated.initial_balances.get(&id) {
                assert_eq!(*existing_balance, balance);
            } else {
                self.replicated.initial_balances.insert(id, balance);
            }
        }

        for (id, hist) in other.hist {
            let account_hist = self.replicated.hist.entry(id).or_default();
            account_hist.extend(hist);
        }
    }

    /// Executed once an op has been validated
    fn deliver(&mut self, from: Actor, op: Op) {
        // In the paper, we would increment rec[from] because we buffer transfers until
        // they become valid, but in our implementation we do not buffer, and as such
        // the seq[from] clock and the rec[from] clock would be identical.

        if self.validate(&from, &op) {
            match op {
                Op::Transfer(transfer) => {
                    // Update the history for the outgoing account
                    self.replicated
                        .hist
                        .entry(transfer.from)
                        .or_default()
                        .insert(transfer.clone());

                    // Update the history for the incoming account
                    self.replicated
                        .hist
                        .entry(transfer.to)
                        .or_default()
                        .insert(transfer.clone());

                    self.seq.apply(Dot {
                        actor: from,
                        counter: transfer.seq_num,
                    });

                    if transfer.to == self.id {
                        self.deps.insert(transfer.clone());
                    }

                    if transfer.from == self.id {
                        // In the paper, deps are cleared after the broadcast completes in
                        // self.transfer.
                        // Here we break up the initiation of the transfer from the completion.
                        // We move the clearing of the deps here since this is where we now know
                        // the transfer was successfully validated and applied by the network.
                        for prior_transfer in transfer.deps.iter() {
                            // for each dependency listed in the transfer
                            // we remove it from the set of dependencies for a transfer
                            self.deps.remove(prior_transfer);
                        }
                    }
                }
                Op::OpenAccount { owner, balance } => {
                    println!("[BANK] opening new account for {} with ${}", owner, balance);
                    self.replicated.initial_balances.insert(owner, balance);
                }
            }
        }
    }
}
