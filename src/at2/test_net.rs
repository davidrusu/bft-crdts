use std::collections::HashSet;

use crate::at2::bank::{Account, Money};
use crate::at2::deterministic_secure_broadcast::SecureBroadcastProc;
use crate::at2::identity::Identity;

#[derive(Debug, Default)]
struct Net {
    procs: Vec<SecureBroadcastProc>,
}

impl Net {
    fn new(n: usize) -> Self {
        let mut procs = Vec::new();
        for _ in 0..n {
            procs.push(SecureBroadcastProc::new_with_balance(1000))
        }

        Self { procs }
    }

    fn identities(&self) -> HashSet<Identity> {
        self.procs.iter().map(|p| p.identity()).collect()
    }

    fn read_balance_from_pov_of_proc(&self, pov: Identity, account: Account) -> Option<Money> {
        self.procs
            .iter()
            .find(|secure_p| secure_p.identity() == pov)
            .map(|secure_p| secure_p.read_state(|p| p.read(account)))
    }

    fn transfer(&mut self, source: Identity, from: Account, to: Account, amount: Money) {
        let source_proc = self
            .procs
            .iter_mut()
            .find(|p| p.identity() == source)
            .expect("[ERROR] invalid source proc");

        let msgs = source_proc.exec(|p| p.transfer(from, to, amount));
        println!("Source proc executing msgs: {:?}", msgs);

        // TODO: execute delivery of msgs
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
                    deps: BTreeSet::new(),
                },
                source_version: Dot::new(32, 1),
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
                    deps: BTreeSet::new(),
                },
                source_version: Dot::new(32, 1),
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
