// IMPLEMENTATION OF https://arxiv.org/pdf/1812.10844.pdf

// TODO: remove unused derives
use std::collections::{BTreeSet, HashMap}; // TODO: can we replace HashMap with BTreeMap
use std::mem;

type ProcID = u8;
type Money = i64;

#[derive(Debug)]
struct Proc {
    id: ProcID,
    initial_balances: HashMap<ProcID, Money>,
    seq: HashMap<ProcID, u64>, // Number of validated transfers outgoing from q
    rec: HashMap<ProcID, u64>, // Number of delivered transfers from q
    hist: HashMap<ProcID, BTreeSet<Transfer>>, // Set of validated transfers involving q
    deps: BTreeSet<Transfer>,  // Set of last incoming transfers for account of local process p
    to_validate: BTreeSet<(ProcID, Msg)>, // Set of delivered (but not validated) transfers
    peers: BTreeSet<ProcID>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Transfer {
    from: ProcID,
    to: ProcID,
    amount: Money,
    seq_num: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Msg {
    transfer: Transfer,
    history: BTreeSet<Transfer>,
}

impl Proc {
    fn new(id: ProcID, initial_balance: Money) -> Self {
        Proc {
            id,
            initial_balances: vec![(id, initial_balance)].into_iter().collect(),
            seq: HashMap::new(),
            rec: HashMap::new(),
            hist: HashMap::new(),
            deps: BTreeSet::new(),
            to_validate: BTreeSet::new(),
            peers: BTreeSet::new(),
        }
    }

    fn onboard(&mut self, peers: Vec<ProcID>) -> Vec<Cmd> {
        let initial_balance = self.initial_balance_for_proc(self.id);

        peers
            .iter()
            .cloned()
            .map(|peer_id| Cmd::JoinRequest {
                to: peer_id,
                proc_to_join: self.id,
                initial_balance,
            })
            .collect()
    }

    fn transfer(&mut self, from: ProcID, to: ProcID, amount: Money) -> Vec<Cmd> {
        assert_eq!(from, self.id);

        if self.read(from) < amount {
            // not enough money in the account to complete the transfer
            vec![]
        } else {
            vec![Cmd::BroadcastMsg {
                from: self.id,
                msg: Msg {
                    transfer: Transfer {
                        from,
                        to,
                        amount,
                        seq_num: self.seq_for_proc(from) + 1,
                    },
                    history: self.deps.clone(),
                },
            }]
        }
    }

    fn read(&self, account: ProcID) -> Money {
        self.balance(
            account,
            &self
                .hist_for_proc(account)
                .union(&self.deps)
                .cloned()
                .collect(),
        )
    }

    /// Executed when we successfully deliver messages to process p
    fn on_delivery(&mut self, from: ProcID, msg: Msg) {
        assert_eq!(from, msg.transfer.from);

        // Secure broadcast callback
        if msg.transfer.seq_num == *self.rec.entry(msg.transfer.from).or_default() + 1 {
            println!(
                "{} Accepted message from {} and enqueued for validation",
                self.id, from
            );
            let from_rec = self.rec.entry(from).or_default();
            *from_rec += 1;

            self.to_validate.insert((from, msg));
        } else {
            println!(
                "{} Rejected message from {}, transfer seq_num is invalid",
                self.id, from
            );
        }
    }

    /// Executed when a transfer from `from` becomes valid.
    fn on_validated(&mut self, from: ProcID, msg: &Msg) {
        assert!(self.valid(from, &msg));
        assert_eq!(self.seq_for_proc(from) + 1, msg.transfer.seq_num);

        // Update the history for the outgoing account
        self.hist
            .entry(msg.transfer.from)
            .or_default()
            .insert(msg.transfer);

        // Update the history for the incoming account
        self.hist
            .entry(msg.transfer.to)
            .or_default()
            .insert(msg.transfer);

        self.seq.insert(from, msg.transfer.seq_num);

        if msg.transfer.to == self.id {
            // This transfer directly affects the account of this process.
            // THUS, it becomes a dependancy of the next transfer executed by this process.
            self.deps.insert(msg.transfer);
        }

        if msg.transfer.from == self.id {
            // This transfer is outgoing from account of local process (it was sent by this proc)

            // In the paper, they clear the deps after the broadcast completes
            // in self.transfer, we use an event model here so we can't guarantee
            // the broadcast completes successfully from within the transfer function.
            // We move the clearing of the deps here since this is where we now know
            // the broadcast succeeded
            self.deps = BTreeSet::new();
        }
    }

    fn valid(&self, from: ProcID, msg: &Msg) -> bool {
        let last_known_sender_seq = self.seq_for_proc(from);
        let balance_of_sender = self.balance(msg.transfer.from, &self.hist_for_proc(from));
        let sender_history = self.hist_for_proc(from);

        if from != msg.transfer.from {
            println!(
                "[INVALID] sending proc {} does not match msg from field: {}",
                from, msg.transfer.from
            );
            false
        } else if msg.transfer.seq_num != last_known_sender_seq + 1 {
            println!(
                "[INVALID] seq {} is not a direct successor of last transfer from {}: {}",
                msg.transfer.seq_num, from, last_known_sender_seq
            );
            false
        } else if balance_of_sender < msg.transfer.amount {
            println!(
                "[INVALID] balance of sending proc is not sufficient for transfer: {} < {}",
                balance_of_sender, msg.transfer.amount
            );
            false
        } else if !msg.history.is_subset(&sender_history) {
            println!(
                "[INVALID] known history of sender {:?} not subset of msg history {:?}",
                msg.history, sender_history
            );
            false
        } else {
            true
        }
    }

    fn seq_for_proc(&self, p: ProcID) -> u64 {
        self.seq.get(&p).cloned().unwrap_or_default()
    }

    fn hist_for_proc(&self, p: ProcID) -> BTreeSet<Transfer> {
        self.hist.get(&p).cloned().unwrap_or_default()
    }

    fn initial_balance_for_proc(&self, p: ProcID) -> Money {
        self.initial_balances
            .get(&p)
            .cloned()
            .expect(&format!("[ERROR] No initial balance for proc {}", p))
    }

    fn balance(&self, a: ProcID, h: &BTreeSet<Transfer>) -> Money {
        let outgoing: Money = h.iter().filter(|t| t.from == a).map(|t| t.amount).sum();
        let incoming: Money = h.iter().filter(|t| t.to == a).map(|t| t.amount).sum();

        let balance_delta = incoming - outgoing;

        let balance = self.initial_balance_for_proc(a) + balance_delta;

        assert!(balance >= 0);

        balance
    }

    fn handle_join_request(&mut self, new_proc: ProcID, initial_balance: Money) -> Vec<Cmd> {
        if !self.peers.contains(&new_proc) {
            self.peers.insert(new_proc);
            self.initial_balances.insert(new_proc, initial_balance);

            vec![Cmd::JoinRequest {
                to: new_proc,
                proc_to_join: self.id,
                initial_balance: self.initial_balance_for_proc(self.id),
            }]
        } else {
            vec![]
        }
    }

    fn handle_msg(&mut self, from: ProcID, msg: Msg) -> Vec<Cmd> {
        self.on_delivery(from, msg);
        self.process_msg_queue();
        vec![]
    }

    fn process_msg_queue(&mut self) {
        let to_validate = mem::replace(&mut self.to_validate, BTreeSet::new());
        for (to, msg) in to_validate {
            if self.valid(to, &msg) {
                self.on_validated(to, &msg);
            } else {
                println!("[DROP] invalid message detected {:?}", (to, msg));
            }
        }
    }
}

#[derive(Debug, Default)]
struct Net {
    procs: HashMap<ProcID, Proc>,
}

#[derive(Debug)]
enum Cmd {
    JoinRequest {
        to: ProcID,
        proc_to_join: ProcID,
        initial_balance: Money,
    },
    BroadcastMsg {
        from: ProcID,
        msg: Msg,
    },
}

impl Net {
    fn add_proc(&mut self, id: ProcID, initial_balance: Money) {
        assert!(!self.procs.contains_key(&id));
        let peers = self.procs.keys().cloned().collect();
        let mut new_proc = Proc::new(id, initial_balance);
        let proc_onboarding_cmds = new_proc.onboard(peers);

        self.procs.insert(id, new_proc);

        self.step_until_done(proc_onboarding_cmds);
    }

    fn read_balance_from_perspective_of_proc(&self, id: ProcID, account: ProcID) -> Money {
        self.procs
            .get(&id)
            .map(|p| p.read(account))
            .expect("[ERROR] No proc by that name")
    }

    fn transfer(&mut self, source: ProcID, from: ProcID, to: ProcID, amount: Money) {
        let source_proc = self
            .procs
            .get_mut(&source)
            .expect("[ERROR] invalid source proc");
        let cmds = source_proc.transfer(from, to, amount);
        self.step_until_done(cmds);
    }

    fn step_until_done(&mut self, initial_cmds: Vec<Cmd>) {
        let mut cmd_queue = initial_cmds;
        while let Some(cmd) = cmd_queue.pop() {
            println!("CMD: {:?}", cmd);
            cmd_queue.extend(self.handle_cmd(cmd));
        }
    }

    fn handle_cmd(&mut self, cmd: Cmd) -> Vec<Cmd> {
        match cmd {
            Cmd::JoinRequest {
                to,
                proc_to_join,
                initial_balance,
            } => self.handle_join_request(to, proc_to_join, initial_balance),
            Cmd::BroadcastMsg { from, msg } => self.handle_broadcast_msg(from, msg),
        }
    }

    fn handle_join_request(
        &mut self,
        to: ProcID,
        new_proc: ProcID,
        initial_balance: Money,
    ) -> Vec<Cmd> {
        let to_proc = self
            .procs
            .get_mut(&to)
            .expect("[ERROR] invalid source proc");

        to_proc.handle_join_request(new_proc, initial_balance)
    }

    fn handle_broadcast_msg(&mut self, from: ProcID, msg: Msg) -> Vec<Cmd> {
        let mut causal_nexts: Vec<Cmd> = Vec::new();
        for (to, proc) in self.procs.iter_mut() {
            if to == &from {
                continue;
            }
            causal_nexts.extend(proc.handle_msg(from, msg.clone()));
        }

        // Signal to the sending that it's safe to apply the transfer
        let next_cmds_triggered_by_msg = self
            .procs
            .get_mut(&from)
            .expect(&format!("[ERROR] No proc with ProcID {}", from))
            .handle_msg(from, msg);

        causal_nexts.extend(next_cmds_triggered_by_msg);

        causal_nexts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_balance() {
        let mut net = Net::default();

        net.add_proc(32, 1000);

        let balance_of_32 = net.read_balance_from_perspective_of_proc(32, 32);
        assert_eq!(balance_of_32, 1000);
    }

    #[test]
    fn test_transfer() {
        let mut net = Net::default();

        net.add_proc(32, 1000);
        net.add_proc(91, 0);

        assert_eq!(net.read_balance_from_perspective_of_proc(32, 32), 1000);
        assert_eq!(net.read_balance_from_perspective_of_proc(91, 91), 0);

        net.transfer(32, 32, 91, 1000);

        assert_eq!(net.read_balance_from_perspective_of_proc(32, 32), 0);
        assert_eq!(net.read_balance_from_perspective_of_proc(91, 91), 1000);
    }

    #[test]
    fn test_double_spend() {
        let mut net = Net::default();

        net.add_proc(32, 1000);
        net.add_proc(91, 0);
        net.add_proc(54, 0);

        assert_eq!(net.read_balance_from_perspective_of_proc(32, 32), 1000);
        assert_eq!(net.read_balance_from_perspective_of_proc(91, 91), 0);
        assert_eq!(net.read_balance_from_perspective_of_proc(54, 54), 0);

        net.step_until_done(vec![Cmd::BroadcastMsg {
            from: 32,
            msg: Msg {
                transfer: Transfer {
                    from: 32,
                    to: 91,
                    amount: 1000,
                    seq_num: 1,
                },
                history: BTreeSet::new(),
            },
        }]);

        assert_eq!(net.read_balance_from_perspective_of_proc(32, 32), 0);
        assert_eq!(net.read_balance_from_perspective_of_proc(91, 91), 1000);
        assert_eq!(net.read_balance_from_perspective_of_proc(54, 54), 0);

        net.step_until_done(vec![Cmd::BroadcastMsg {
            from: 32,
            msg: Msg {
                transfer: Transfer {
                    from: 32,
                    to: 54,
                    amount: 1000,
                    seq_num: 1,
                },
                history: BTreeSet::new(),
            },
        }]);

        // Verify double spend was caught
        assert_eq!(net.read_balance_from_perspective_of_proc(32, 32), 0);
        assert_eq!(net.read_balance_from_perspective_of_proc(91, 91), 1000);
        assert_eq!(net.read_balance_from_perspective_of_proc(54, 54), 0);
    }

    #[test]
    fn test_causal_dependancy() {
        let mut net = Net::default();

        net.add_proc(32, 1000);
        net.add_proc(91, 1000);
        net.add_proc(54, 1000);
        net.add_proc(16, 1000);

        assert_eq!(net.read_balance_from_perspective_of_proc(32, 32), 1000);
        assert_eq!(net.read_balance_from_perspective_of_proc(91, 91), 1000);
        assert_eq!(net.read_balance_from_perspective_of_proc(54, 54), 1000);
        assert_eq!(net.read_balance_from_perspective_of_proc(16, 16), 1000);

        // T0:  32 -> 91
        net.transfer(32, 32, 91, 500);

        // T1: 32 -> 54
        net.transfer(32, 32, 54, 500);

        // T2: 91 -> 16
        net.transfer(91, 91, 16, 1500);

        assert_eq!(net.read_balance_from_perspective_of_proc(32, 32), 0);
        assert_eq!(net.read_balance_from_perspective_of_proc(91, 91), 0);
        assert_eq!(net.read_balance_from_perspective_of_proc(54, 54), 1500);
        assert_eq!(net.read_balance_from_perspective_of_proc(16, 16), 2500);
    }
}
