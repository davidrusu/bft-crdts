use std::collections::{HashMap, HashSet};

pub type Identity = u8;
pub type Account = Identity; // In the paper, Identity and Account are synonymous
pub type Money = i64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Transfer {
    pub from: Account,
    pub to: Account,
    pub amount: Money,
}

impl Transfer {
    /// These affected accounts become causally dependent on this operation.
    pub fn affected_accounts(&self) -> HashSet<Account> {
        vec![self.from, self.to].into_iter().collect()
    }
}

#[derive(Debug)]
pub struct Bank {
    initial_balances: HashMap<Account, Money>,
    // Set of all transfers impacting a given account
    hist: HashMap<Account, HashSet<Transfer>>,
}

impl Bank {
    pub fn new() -> Self {
        Bank {
            initial_balances: HashMap::new(),
            hist: HashMap::new(),
        }
    }

    pub fn open_account(&mut self, account: Account, initial_balance: Money) {
        self.initial_balances.insert(account, initial_balance);
    }

    pub fn initial_balance(&self, account: &Account) -> Money {
        self.initial_balances
            .get(&account)
            .cloned()
            .expect(&format!(
                "[ERROR] No initial balance for account {}",
                account
            ))
    }

    pub fn read(&self, acc: &Account) -> Money {
        self.balance(acc)
    }

    fn balance(&self, acc: &Account) -> Money {
        // TODO: in the paper, when we read from an account, we union the account
        //       history with the deps, I don't see a use for this since anything
        //       in deps is already in the account history. Think this through a
        //       bit more carefully.
        let h = self.history(&acc);

        let outgoing: Money = h.iter().filter(|t| t.from == *acc).map(|t| t.amount).sum();
        let incoming: Money = h.iter().filter(|t| t.to == *acc).map(|t| t.amount).sum();

        let balance_delta = incoming - outgoing;
        let balance = self.initial_balance(acc) + balance_delta;

        assert!(balance >= 0);

        balance
    }

    fn history(&self, account: &Account) -> HashSet<Transfer> {
        self.hist.get(account).cloned().unwrap_or_default()
    }

    pub fn transfer(&self, from: Account, to: Account, amount: Money) -> Option<Transfer> {
        let balance = self.balance(&from);
        if balance < amount {
            println!(
                "Not enough money in {} account to transfer {} to {}. (balance: {})",
                from, amount, to, balance
            );
            None
        } else {
            Some(Transfer { from, to, amount })
        }
    }

    /// Protection against Byzantines
    pub fn validate(&self, source_proc: Identity, op: &Transfer) -> bool {
        let balance_of_sender = self.read(&op.from);

        if op.from != source_proc {
            println!(
                "[INVALID] Transfer from {:?} was was initiated by a proc that does not own this account: {:?}",
                source_proc, op.from
            );
            false
        } else if balance_of_sender < op.amount {
            println!(
                "[INVALID] balance of sending proc is not sufficient for transfer: {} < {}",
                balance_of_sender, op.amount
            );
            false
        } else {
            true
        }
    }

    /// Executed once an op has been validated
    pub fn apply(&mut self, op: Transfer) {
        // Update the history for the outgoing account
        self.hist.entry(op.from).or_default().insert(op);

        // Update the history for the incoming account
        self.hist.entry(op.to).or_default().insert(op);
    }
}
