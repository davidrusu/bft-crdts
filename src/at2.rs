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
    deps: BTreeSet<Transfer>, // Set of last incoming transfers for account of local process p
    to_validate: BTreeSet<(ProcID, Msg)>, // Set of delivered (but not validated) transfers
    peers: BTreeSet<ProcID>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Transfer {
    from: ProcID,
    to: ProcID,
    amount: Money,
    seq_num: u64
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Msg {
    transfer: Transfer,
    history: BTreeSet<Transfer>
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
        let initial_balance = self.initial_balances
            .get(&self.id)
            .cloned()
            .expect("[ERROR] proc does not have initial balance");

        peers
            .iter()
            .cloned()
            .map(|peer_id| Cmd::JoinRequest{ to: peer_id, proc_to_join: self.id, initial_balance})
            .collect()
    }

    fn transfer(&mut self, from: ProcID, to: ProcID, amount: Money) -> Vec<Cmd> {
        assert_eq!(from, self.id);

        if self.read(from) < amount {
            // not enough money in the account to complete the transfer
            vec![]
        } else {
            let seq_num = self.seq.get(&from).cloned().unwrap_or_default() + 1;
            

            vec![
                Cmd::BroadcastMsg {
                    from: self.id,
                    msg: Msg {
                        transfer: Transfer { from, to, amount, seq_num },
                        history: self.deps.clone()
                    }
                }
            ]
        }
    }

    fn read(&self, account: ProcID) -> Money {
        self.balance(account, &self.hist.get(&account).cloned().unwrap_or_default().union(&self.deps).cloned().collect())
    }

    /// Executed when we successfully deliver messages to process p
    fn on_delivery(&mut self, from: ProcID, msg: Msg) {
        assert_eq!(from, msg.transfer.from);

        // Secure broadcast callback
        if msg.transfer.seq_num  == *self.rec.entry(msg.transfer.from).or_default() + 1 {
            println!("Accepted message and enqueued for validation");
            let from_rec = self.rec.entry(from).or_default();
            *from_rec += 1;

            self.to_validate.insert((from, msg));
        } else {
            println!("Rejected message since transfer seq_num is invalid");
        }
    }

    /// Executed when a transfer from `from` becomes valid.
    fn on_validated(&mut self, from: ProcID, msg: &Msg) {
        assert!(self.valid(from, &msg));
        let from_hist = self.hist.entry(msg.transfer.from).or_default();
        from_hist.insert(msg.transfer); // Update the history for the outgoing account

        let to_hist = self.hist.entry(msg.transfer.to).or_default();
        to_hist.insert(msg.transfer); // Update the history for the incoming account

        self.seq.insert(from, msg.transfer.seq_num);

        if msg.transfer.to == self.id {
            // This transfer is directly affects the account of this process.
            // THUS, it becomes a dependancy of the next transfer executed by this process.
            self.deps.insert(msg.transfer);
        } else if msg.transfer.from == self.id {
            // This transfer is outgoing from account of local process
        }
    }

    fn valid(&self, from: ProcID, msg: &Msg) -> bool {
        let last_known_sender_seq = self.seq.get(&from).cloned().unwrap_or_default();
        if from != msg.transfer.from {
            println!("[INVALID] sending proc does not match msg from field");
            false
        } else if msg.transfer.seq_num != last_known_sender_seq + 1 {
            println!("[INVALID] sequence number is not a direct suc of the last transfer from {}: {}", from, last_known_sender_seq);
            false
        } else if self.balance(msg.transfer.from, &self.hist.get(&from).cloned().unwrap_or_default()) < msg.transfer.amount {
            println!("[INVALID] balance of sending proc is not sufficient for transfer");
            false
        } else if !self.hist.get(&from).cloned().unwrap_or_default().is_subset(&msg.history) {
            println!("[INVALID] known history of sender is not a subset of the msg history");
            false
        } else {
            true
        }
    }

    fn balance(&self, a: ProcID, h: &BTreeSet<Transfer>) -> Money {
        let outgoing: Money = h.iter().filter(|t| t.from == a).map(|t| t.amount).sum();
        let incoming: Money = h.iter().filter(|t| t.to== a).map(|t| t.amount).sum();
        let initial_balance: Money = self.initial_balances.get(&a).cloned().expect("[ERROR] No initial balance for proc");

        let balance_delta = incoming - outgoing;
        
        let balance = balance_delta + initial_balance;

        assert!(balance >= 0);

        balance 
    }

    fn handle_join_request(&mut self, new_proc: ProcID, initial_balance: Money) -> Vec<Cmd> {
        if !self.peers.contains(&new_proc) {
            self.peers.insert(new_proc);
            self.initial_balances.insert(new_proc, initial_balance);
            
            let initial_balance: Money = self.initial_balances.get(&self.id)
                .cloned()
                .expect("[ERROR] No initial balance for self");
            vec![Cmd::JoinRequest { to: new_proc, proc_to_join: self.id, initial_balance}]
        } else {
            vec![]
        }
    }

    fn handle_msg(&mut self, from: ProcID, msg: Msg) -> Vec<Cmd> {
        self.on_delivery(from, msg.clone());
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
    procs: HashMap<ProcID, Proc>    
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
    }
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
        self.procs.get(&id).map(|p| p.read(account)).expect("[ERROR] No proc by that name")
    }

    fn transfer(&mut self, source: ProcID, from: ProcID, to: ProcID, amount: Money) {

        let source_proc = self.procs
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
            dbg!(&self);
        }
    }

    fn handle_cmd(&mut self, cmd: Cmd) -> Vec<Cmd> {
        match cmd {
            Cmd::JoinRequest { to, proc_to_join, initial_balance } => self.handle_join_request(to, proc_to_join, initial_balance),
            Cmd::BroadcastMsg { from, msg } => self.handle_broadcast_msg(from, msg),
        }
    }

    fn handle_join_request(&mut self, to: ProcID, new_proc: ProcID, initial_balance: Money) -> Vec<Cmd> {
        let to_proc = self.procs
            .get_mut(&to)
            .expect(&format!("[ERROR] invalid source proc"));

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
        let from_proc = self.procs.get_mut(&from).expect("[ERROR] missing from proc");
        causal_nexts.extend(from_proc.handle_msg(from, msg)); 

        return causal_nexts;
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

        net.step_until_done(vec![
            Cmd::BroadcastMsg {
                from: 32,
                msg: Msg {
                    transfer: Transfer { from: 32, to: 91, amount: 1000, seq_num: 1 },
                    history: BTreeSet::new()
                }
            }
        ]);

        assert_eq!(net.read_balance_from_perspective_of_proc(32, 32), 0);
        assert_eq!(net.read_balance_from_perspective_of_proc(91, 91), 1000);
        assert_eq!(net.read_balance_from_perspective_of_proc(54, 54), 0);
        
        net.step_until_done(vec![
            Cmd::BroadcastMsg {
                from: 32,
                msg: Msg {
                    transfer: Transfer { from: 32, to: 54, amount: 1000, seq_num: 1},
                    history: BTreeSet::new()
                }
            }
        ]);

        // Verify double spend was caught
        assert_eq!(net.read_balance_from_perspective_of_proc(32, 32), 0);
        assert_eq!(net.read_balance_from_perspective_of_proc(91, 91), 1000);
        assert_eq!(net.read_balance_from_perspective_of_proc(54, 54), 0);
    }

    // #[test]
    // fn test_causal_dependancy() {
    //     let mut net = Net::default();

    //     net.add_proc(32, 100);
    //     net.add_proc(91, 100);
    //     net.add_proc(54, 100);
    //     net.add_proc(16, 100);

        
    //     assert_eq!(net.read_balance_from_perspective_of_proc(32, 32), 1000);
    // }
}
