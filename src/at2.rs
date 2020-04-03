// IMPLEMENTATION OF https://arxiv.org/pdf/1812.10844.pdf

// TODO: remove unused derives
use std::collections::{HashMap, HashSet};
use std::mem;

use crdts::vclock::{Dot, VClock};
use crdts::CmRDT;

type ProcID = u8;
type Money = i64;

#[derive(Debug)]
struct Proc {
    id: ProcID,
    initial_balances: HashMap<ProcID, Money>,
    // Applied knowledged by ProcID
    seq: VClock<ProcID>,
    // Delivered but not neccessarily applied knowledge by ProcID
    rec: VClock<ProcID>,
    // Set of validated transfers involving a given Proc
    hist: HashMap<ProcID, HashSet<Transfer>>,
    // Set of last incoming transfers for account of local process p
    deps: HashSet<Transfer>,
    // Set of delivered (but not validated) transfers
    to_validate: Vec<(ProcID, Msg)>,
    peers: HashSet<ProcID>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Transfer {
    from: ProcID,
    to: ProcID,
    amount: Money,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Msg {
    transfer: Transfer,
    source_version: Dot<ProcID>,
    history: HashSet<Transfer>,
}

impl Proc {
    fn new(id: ProcID, initial_balance: Money) -> Self {
        Proc {
            id,
            initial_balances: vec![(id, initial_balance)].into_iter().collect(),
            seq: VClock::new(),
            rec: VClock::new(),
            hist: HashMap::new(),
            deps: HashSet::new(),
            to_validate: Vec::new(),
            peers: HashSet::new(),
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
                    transfer: Transfer { from, to, amount },
                    source_version: self.seq.inc(from),
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

    fn balance(&self, a: ProcID, h: &HashSet<Transfer>) -> Money {
        let outgoing: Money = h.iter().filter(|t| t.from == a).map(|t| t.amount).sum();
        let incoming: Money = h.iter().filter(|t| t.to == a).map(|t| t.amount).sum();

        let balance_delta = incoming - outgoing;

        let balance = self.initial_balance_for_proc(a) + balance_delta;

        assert!(balance >= 0);

        balance
    }

    /// Executed when we successfully deliver messages to process p
    fn on_delivery(&mut self, from: ProcID, msg: Msg) {
        assert_eq!(from, msg.source_version.actor);

        // Secure broadcast callback
        if msg.source_version == self.rec.inc(from) {
            println!(
                "{} Accepted message from {} and enqueued for validation",
                self.id, from
            );
            self.rec.apply(msg.source_version);
            self.to_validate.push((from, msg));
        } else {
            println!(
                "{} Rejected message from {}, transfer source version is invalid: {:?}",
                self.id, from, msg.source_version
            );
        }
    }

    /// Executed when a transfer from `from` becomes valid.
    fn on_validated(&mut self, from: ProcID, msg: &Msg) {
        assert!(self.valid(from, &msg));
        assert_eq!(msg.source_version, self.seq.inc(from));

        // Update the history for the outgoing account
        self.hist
            .entry(msg.source_version.actor)
            .or_default()
            .insert(msg.transfer);

        // Update the history for the incoming account
        self.hist
            .entry(msg.transfer.to)
            .or_default()
            .insert(msg.transfer);

        self.seq.apply(msg.source_version);

        if msg.transfer.to == self.id {
            // This transfer directly affects the account of this process.
            // THUS, it becomes a dependancy of the next transfer executed by this process.
            self.deps.insert(msg.transfer);
        }

        if msg.source_version.actor == self.id {
            // This transfer is outgoing from account of local process (it was sent by this proc)

            // In the paper, they clear the deps after the broadcast completes
            // in self.transfer, we use an event model here so we can't guarantee
            // the broadcast completes successfully from within the transfer function.
            // We move the clearing of the deps here since this is where we now know
            // the broadcast succeeded
            self.deps.clear();
        }
    }

    fn valid(&self, from: ProcID, msg: &Msg) -> bool {
        let balance_of_sender = self.balance(msg.source_version.actor, &self.hist_for_proc(from));
        let sender_history = self.hist_for_proc(from);

        if from != msg.source_version.actor {
            println!(
                "[INVALID] Transfer from {:?} does not match the msg source version {:?}",
                from, msg.source_version
            );
            false
        } else if msg.transfer.from != msg.source_version.actor {
            println!(
                "[INVALID] Transfer from {:?} does not have matching the msg source version and msg transfer from fields {:?} != {:?}",
                from, msg.source_version, msg.transfer.from
            );
            false
        } else if msg.source_version != self.seq.inc(from) {
            println!(
                "[INVALID] Source version {:?} is not a direct successor of last transfer from {}: {:?}",
                msg.source_version, from, self.seq.dot(from)
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

    fn hist_for_proc(&self, p: ProcID) -> HashSet<Transfer> {
        self.hist.get(&p).cloned().unwrap_or_default()
    }

    fn initial_balance_for_proc(&self, p: ProcID) -> Money {
        self.initial_balances
            .get(&p)
            .cloned()
            .expect(&format!("[ERROR] No initial balance for proc {}", p))
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
        let to_validate = mem::replace(&mut self.to_validate, Vec::new());
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
                },
                source_version: Dot::new(32, 1),
                history: HashSet::new(),
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
                },
                source_version: Dot::new(32, 1),
                history: HashSet::new(),
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
