use std::collections::{BTreeSet, HashMap};

use serde::Serialize;

use crate::at2::identity::Identity;
use crate::at2::traits::SecureBroadcastAlgorithm;

// TODO: introduce decomp. of Account from Identity
// pub type Account = Identity; // In the paper, Identity and Account are synonymous

pub type Money = u64;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum Op {
    Transfer(Transfer), // Split out Transfer into it's own struct to get some more type safety in Bank struct
    OpenAccount { owner: Identity, balance: Money },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
struct Transfer {
    from: Identity,
    to: Identity,
    amount: Money,

    /// set of transactions that need to be applied before this transfer can be validated
    /// ie. a proof of funds
    deps: BTreeSet<Transfer>,
}

#[derive(Debug, Clone)]
pub struct Bank {
    id: Identity,

    // When a new identity is created, it will be given an initial balance
    initial_balances: HashMap<Identity, Money>,

    // Set of all transfers impacting a given identity
    hist: HashMap<Identity, BTreeSet<Transfer>>, // TODO: Opening an account should be part of history

    // The set of dependencies of the next outgoing transfer
    deps: BTreeSet<Transfer>,
}

impl Bank {
    pub fn open_account(&self, owner: Identity, balance: Money) -> Op {
        Op::OpenAccount { owner, balance }
    }

    pub fn initial_balance(&self, identity: &Identity) -> Money {
        self.initial_balances
            .get(&identity)
            .cloned()
            .unwrap_or_else(|| panic!("[ERROR] No initial balance for {}", identity))
    }

    pub fn balance(&self, identity: &Identity) -> Money {
        // TODO: in the paper, when we read from an identity, we union the identity
        //       history with the deps, I don't see a use for this since anything
        //       in deps is already in the identity history. Think this through a
        //       bit more carefully.
        let h = self.history(identity);

        let outgoing: Money = h
            .iter()
            .filter(|t| &t.from == identity)
            .map(|t| t.amount)
            .sum();
        let incoming: Money = h
            .iter()
            .filter(|t| &t.to == identity)
            .map(|t| t.amount)
            .sum();

        // We compute differences in a larger space since we need to move to signed numbers
        // and hence we lose a bit.
        let balance_delta: i128 = (incoming as i128) - (outgoing as i128);
        let balance: i128 = self.initial_balance(identity) as i128 + balance_delta;

        assert!(balance >= 0); // sanity check that we haven't violated our balance constraint
        assert!(balance <= Money::max_value() as i128); // sanity check that it's safe to downcast

        balance as Money
    }

    fn history(&self, identity: &Identity) -> BTreeSet<Transfer> {
        self.hist.get(&identity).cloned().unwrap_or_default()
    }

    pub fn transfer(&self, from: Identity, to: Identity, amount: Money) -> Option<Op> {
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
            Some(Op::Transfer(Transfer {
                from,
                to,
                amount,
                deps,
            }))
        }
    }
}

impl SecureBroadcastAlgorithm for Bank {
    type Op = Op;

    fn new(id: Identity) -> Self {
        Bank {
            id,
            initial_balances: Default::default(),
            hist: Default::default(),
            deps: Default::default(),
        }
    }

    fn sync_from(&mut self, other: Self) {
        // TODO: this is not ideal, we dont want to ship the entire local state over
        // ie. id and deps are not needed

        for (id, balance) in other.initial_balances {
            if let Some(existing_balance) = self.initial_balances.get(&id) {
                assert_eq!(*existing_balance, balance);
            } else {
                self.initial_balances.insert(id, balance);
            }
        }

        for (id, hist) in other.hist {
            let account_hist = self.hist.entry(id).or_default();
            account_hist.extend(hist);
        }
    }

    /// Protection against Byzantines
    fn validate(&self, from: &Identity, op: &Op) -> bool {
        let validation_tests = match op {
            Op::Transfer(transfer) => vec![
                (
                    from == &transfer.from,
                    "Sender initiated transfer on behalf of other proc",
                ),
                (
                    self.balance(from) >= transfer.amount,
                    "Sender has insufficient funds",
                ),
                (
                    transfer.deps.is_subset(&self.history(from)),
                    "Missing dependent ops",
                ),
                // TODO: ensure from has an account
                // TODO: ensure to has an account
            ],
            Op::OpenAccount { owner, balance } => vec![
                (
                    from == owner,
                    "Initiator is not the owner of the new account",
                ),
                (
                    !self.initial_balances.contains_key(owner),
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

    /// Executed once an op has been validated
    fn apply(&mut self, op: Op) {
        match op {
            Op::Transfer(transfer) => {
                // Update the history for the outgoing account
                self.hist
                    .entry(transfer.from)
                    .or_default()
                    .insert(transfer.clone());

                // Update the history for the incoming account
                self.hist
                    .entry(transfer.to)
                    .or_default()
                    .insert(transfer.clone());

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
                self.initial_balances.insert(owner, balance);
            }
        }
    }
}
