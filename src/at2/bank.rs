use std::collections::{BTreeSet, HashMap};

use serde::Serialize;

use crate::at2::identity::Identity;

// TODO: introduce decomp. of Account from Identity
// pub type Account = Identity; // In the paper, Identity and Account are synonymous

pub type Money = u64;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct Transfer {
    pub from: Identity,
    pub to: Identity,
    pub amount: Money,

    /// set of transactions that need to be applied before this transfer can be validated
    /// ie. a proof of funds
    pub deps: BTreeSet<Transfer>,
}

#[derive(Debug)]
pub struct Bank {
    id: Identity,

    // When a new identity is created, it will be given an initial balance
    initial_balances: HashMap<Identity, Money>,

    // Set of all transfers impacting a given identity
    hist: HashMap<Identity, BTreeSet<Transfer>>,

    // The set of dependencies of the next outgoing transfer
    deps: BTreeSet<Transfer>,
}

impl Bank {
    pub fn new(id: Identity) -> Self {
        Bank {
            id,
            initial_balances: HashMap::new(),
            hist: HashMap::new(),
            deps: BTreeSet::new(),
        }
    }

    pub fn onboard_identity(&mut self, identity: Identity, initial_balance: Money) {
        self.initial_balances.insert(identity, initial_balance);
    }

    pub fn initial_balance(&self, identity: Identity) -> Money {
        self.initial_balances
            .get(&identity)
            .cloned()
            .unwrap_or_else(|| panic!("[ERROR] No initial balance for {}", identity))
    }

    pub fn balance(&self, identity: Identity) -> Money {
        // TODO: in the paper, when we read from an identity, we union the identity
        //       history with the deps, I don't see a use for this since anything
        //       in deps is already in the identity history. Think this through a
        //       bit more carefully.
        let h = self.history(identity);

        let outgoing: Money = h
            .iter()
            .filter(|t| t.from == identity)
            .map(|t| t.amount)
            .sum();
        let incoming: Money = h
            .iter()
            .filter(|t| t.to == identity)
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

    fn history(&self, identity: Identity) -> BTreeSet<Transfer> {
        self.hist.get(&identity).cloned().unwrap_or_default()
    }

    pub fn transfer(&self, from: Identity, to: Identity, amount: Money) -> Option<Transfer> {
        let balance = self.balance(from);
        if balance < amount {
            println!(
                "{} does not have enough money to transfer {} to {}. (balance: {})",
                from, amount, to, balance
            );
            None
        } else {
            let deps = self.deps.clone();
            Some(Transfer {
                from,
                to,
                amount,
                deps,
            })
        }
    }

    /// Protection against Byzantines
    pub fn validate(&self, source_proc: Identity, op: &Transfer) -> bool {
        let balance_of_sender = self.balance(op.from);

        if op.from != source_proc {
            println!(
                "[INVALID] {} initiated a transfer on behalf of another proc: {}",
                source_proc, op.from
            );
            false
        } else if balance_of_sender < op.amount {
            println!(
                "[INVALID] balance of sending proc is not sufficient for transfer: {} < {}",
                balance_of_sender, op.amount
            );

            false
        } else if !op.deps.is_subset(&self.history(op.from)) {
            println!(
                "[INVALID] op deps {:?} is not a subset of the source history: {:?}",
                op.deps,
                self.history(op.from)
            );
            false
        } else {
            true
        }
    }

    /// Executed once an op has been validated
    pub fn apply(&mut self, op: Transfer) {
        // Update the history for the outgoing account
        self.hist.entry(op.from).or_default().insert(op.clone());

        // Update the history for the incoming account
        self.hist.entry(op.to).or_default().insert(op.clone());

        if op.from == self.id {
            // In the paper, deps are cleared after the broadcast completes in
            // self.transfer.
            // Here we break up the initiation of the transfer from the completion.
            // We move the clearing of the deps here since this is where we now know
            // the transfer was successfully validated and applied by the network.
            for op in op.deps.iter() {
                // for each dependency listed in the transfer
                // we remove it from the set of dependencies for a transfer
                self.deps.remove(op);
            }
        }
    }
}
