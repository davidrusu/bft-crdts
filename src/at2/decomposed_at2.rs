/// IMPLEMENTATION OF https://arxiv.org/pdf/1812.10844.pdf
/// Deviations from AT2 as defined in the paper
/// 1.  DONE: we decompose dependency tracking from the distributed algorithm
/// 2.  DONE: we have the entire network tracking the dependancies;
/// 2a. TODO: I think this was a bug in the original paper, email authors to get their thoughts. Not tracking deps at the network level may allow an attackers to convince benign proc's to apply a transfer early.
/// 3.  TODO: we genaralize over the distributed algorithm
/// 4.  TODO: seperate out resources from identity (a process id both identified an agent and an account) we generalize this so that
use std::collections::{HashMap, HashSet};
use std::mem;

use crdts::{CmRDT, Dot, VClock};

use crate::at2::bank::{Account, Bank, Identity, Money, Transfer};

#[derive(Debug, Clone, PartialEq, Eq)]
struct Msg {
    op: Transfer,
    source_version: Dot<Identity>,

    // TODO: now that the network is tracking dependancies, do we need to include them in the msg?
    deps: HashSet<Transfer>,
}

#[derive(Debug)]
struct Proc {
    // The name this process goes by
    id: Identity,
    // The global bank we are keeping in sync across all procs in the network
    bank: Bank,
    // Applied knowledged by Identity
    seq: VClock<Identity>,
    // Delivered but not neccessarily applied knowledge by Identity
    rec: VClock<Identity>,
    // The set of all Op's affecting an account
    hist: HashMap<Account, HashSet<Transfer>>,
    // Set of delivered (but not validated) transfers
    to_validate: Vec<(Identity, Msg)>,
    // Operations that are causally related to the next operation on a given account
    deps: HashMap<Account, HashSet<Transfer>>,
    // The set of known peers. This can likely move to the Secure Broadcast impl.
    peers: HashSet<Identity>,
}

impl Proc {
    fn new(id: Identity, initial_balance: Money) -> Self {
        let mut proc = Proc {
            id,
            bank: Bank::new(),
            seq: VClock::new(),
            rec: VClock::new(),
            hist: HashMap::new(),
            to_validate: Vec::new(),
            deps: HashMap::new(),
            peers: HashSet::new(),
        };

        proc.bank.open_account(id, initial_balance);
        proc
    }

    fn onboard(&mut self, peers: Vec<Identity>) -> Vec<Cmd> {
        let initial_balance = self.bank.initial_balance(&self.id);
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

    fn transfer(&self, from: Identity, to: Identity, amount: Money) -> Vec<Cmd> {
        assert_eq!(from, self.id);
        match self.bank.transfer(from, to, amount) {
            Some(transfer) => vec![Cmd::BroadcastMsg {
                from: from,
                msg: Msg {
                    op: transfer,
                    source_version: self.seq.inc(from),
                    deps: self.deps.get(&from).cloned().unwrap_or_default(),
                },
            }],
            None => vec![],
        }
    }

    fn read(&self, account: &Account) -> Money {
        self.bank.read(&account)
    }

    /// Executed when we successfully deliver messages to process p
    fn on_delivery(&mut self, from: Identity, msg: Msg) {
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
    fn on_validated(&mut self, from: Identity, msg: &Msg) {
        assert!(self.valid(from, &msg));
        assert_eq!(msg.source_version, self.seq.inc(from));
        // sanity check that the source proc had not accepted any new transfers on
        // it's account while this transfer was in progress.
        assert_eq!(
            self.deps
                .get(&msg.source_version.actor)
                .cloned()
                .unwrap_or_default(),
            msg.deps
        );

        // Update history for each affected account
        for account in msg.op.affected_accounts() {
            self.hist.entry(account).or_default().insert(msg.op);
            self.deps.entry(account).or_default().insert(msg.op);
        }

        // TODO: rename Proc::seq to Proc::knowledge ala. VVwE
        // TODO: rename Proc::rec to Proc::forward_knowledge ala. VVwE
        // TODO: add test that "forward_knowleged >= knowledge" is invariant
        self.seq.apply(msg.source_version);

        // This callback tells us that the network has accepted the operation. We must
        // now clear the dependancies of the source proc.
        //
        // In the paper, they clear the deps after the broadcast completes in
        // self.transfer, but since we use an event model here so we can't guarantee
        // the broadcast completes successfully from within the transfer function.
        // We move the clearing of the deps here since this is where we now know
        // the broadcast succeeded.
        self.deps
            .entry(msg.source_version.actor)
            .or_default()
            .clear();

        // Finally, apply the operation to the underlying algorithm
        self.bank.apply(msg.op);
    }

    fn valid(&self, from: Identity, msg: &Msg) -> bool {
        let sender_history = self.hist.get(&from).cloned().unwrap_or_default();
        let affected_accounts = msg.op.affected_accounts();
        let sender_deps = self
            .deps
            .get(&msg.source_version.actor)
            .cloned()
            .unwrap_or_default();

        if sender_deps != msg.deps {
            println!(
                "[INVALID] The msg deps {:?} does not match the expected deps {:?}",
                msg.deps, sender_deps
            );
            false
        } else if !affected_accounts.contains(&from) {
            println!(
                "[INVALID] The source {} is not included in the set of affected accounts {:?}",
                from, affected_accounts
            );
            false
        } else if from != msg.source_version.actor {
            println!(
                "[INVALID] Transfer from {:?} does not match the msg source version {:?}",
                from, msg.source_version
            );
            false
        } else if msg.source_version != self.seq.inc(from) {
            println!(
                "[INVALID] Source version {:?} is not a direct successor of last transfer from {}: {:?}",
                msg.source_version, from, self.seq.dot(from)
            );
            false
        } else if !msg.deps.is_subset(&sender_history) {
            println!(
                "[INVALID] known history of sender {:?} not subset of msg history {:?}",
                msg.deps, sender_history
            );
            false
        } else {
            // Finally, check with the underlying algorithm
            self.bank.validate(from, &msg.op)
        }
    }

    fn handle_join_request(&mut self, new_proc: Identity, initial_balance: Money) -> Vec<Cmd> {
        if !self.peers.contains(&new_proc) {
            self.peers.insert(new_proc);
            self.bank.open_account(new_proc, initial_balance);

            vec![Cmd::JoinRequest {
                to: new_proc,
                proc_to_join: self.id,
                initial_balance: self.bank.initial_balance(&self.id),
            }]
        } else {
            vec![]
        }
    }

    fn handle_msg(&mut self, from: Identity, msg: Msg) -> Vec<Cmd> {
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
    procs: HashMap<Identity, Proc>,
}

#[derive(Debug)]
enum Cmd {
    JoinRequest {
        to: Identity,
        proc_to_join: Identity,
        initial_balance: Money,
    },
    BroadcastMsg {
        from: Identity,
        msg: Msg,
    },
}

impl Net {
    fn add_proc(&mut self, id: Identity, initial_balance: Money) {
        assert!(!self.procs.contains_key(&id));
        let peers = self.procs.keys().cloned().collect();
        let mut new_proc = Proc::new(id, initial_balance);
        let proc_onboarding_cmds = new_proc.onboard(peers);

        self.procs.insert(id, new_proc);

        self.step_until_done(proc_onboarding_cmds);
    }

    fn read_balance_from_perspective_of_proc(&self, id: Identity, account: Identity) -> Money {
        self.procs
            .get(&id)
            .map(|p| p.read(&account))
            .expect("[ERROR] No proc by that name")
    }

    fn transfer(&mut self, source: Identity, from: Identity, to: Identity, amount: Money) {
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
        to: Identity,
        new_proc: Identity,
        initial_balance: Money,
    ) -> Vec<Cmd> {
        let to_proc = self
            .procs
            .get_mut(&to)
            .expect("[ERROR] invalid source proc");

        to_proc.handle_join_request(new_proc, initial_balance)
    }

    fn handle_broadcast_msg(&mut self, from: Identity, msg: Msg) -> Vec<Cmd> {
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
            .expect(&format!("[ERROR] No proc with Identity {}", from))
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

        println!("After adding procs: {:#?}", net);

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
                op: Transfer {
                    from: 32,
                    to: 91,
                    amount: 1000,
                },
                source_version: Dot::new(32, 1),
                deps: HashSet::new(),
            },
        }]);

        assert_eq!(net.read_balance_from_perspective_of_proc(32, 32), 0);
        assert_eq!(net.read_balance_from_perspective_of_proc(91, 91), 1000);
        assert_eq!(net.read_balance_from_perspective_of_proc(54, 54), 0);

        net.step_until_done(vec![Cmd::BroadcastMsg {
            from: 32,
            msg: Msg {
                op: Transfer {
                    from: 32,
                    to: 54,
                    amount: 1000,
                },
                source_version: Dot::new(32, 1),
                deps: HashSet::new(),
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
