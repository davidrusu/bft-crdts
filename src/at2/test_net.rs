use std::collections::{HashMap, HashSet};

use crate::at2::bank::Money;
use crate::at2::deterministic_secure_broadcast::SecureBroadcastProc;
use crate::at2::identity::Identity;

#[derive(Debug)]
struct Net {
    procs: Vec<SecureBroadcastProc>,
}

impl Net {
    fn new(initial_balances: &[Money]) -> Self {
        let mut procs = Vec::new();
        let mut peers_with_balances = HashMap::new();

        for balance in initial_balances.iter().cloned() {
            let proc = SecureBroadcastProc::new();
            peers_with_balances.insert(proc.identity(), balance);
            procs.push(proc);
        }

        for proc in procs.iter_mut() {
            proc.update_peer_list(&peers_with_balances);
        }

        Self { procs }
    }

    fn identities(&self) -> HashSet<Identity> {
        self.procs.iter().map(|p| p.identity()).collect()
    }

    fn balance_from_pov_of_proc(&self, pov: Identity, account: Identity) -> Option<Money> {
        self.procs
            .iter()
            .find(|secure_p| secure_p.identity() == pov)
            .map(|secure_p| secure_p.read_state(|p| p.balance(account)))
    }

    fn transfer(&mut self, initiating_proc: Identity, from: Identity, to: Identity, amount: Money) {
        let msgs = self
            .procs
            .iter_mut()
            .find(|p| p.identity() == initiating_proc)
            .expect("[ERROR] invalid initiating_proc proc")
            .exec(|p| p.transfer(from, to, amount));

        println!("Source proc executing msgs: {:?}", msgs);
        panic!("TODO: execute delivery of msgs");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crdts::quickcheck::quickcheck;

    quickcheck! {
            fn there_is_agreement_on_initial_balances(balances: Vec<Money>) -> bool {
                let mut net = Net::new(&balances);
                let mut known_balances = HashMap::new();

                for identity in net.identities() {
                    let mut remaining_balances = balances.clone();
                    for other_identity in net.identities() {
                        if let Some(balance) = net.balance_from_pov_of_proc(identity, other_identity) {
                            let already_seen_balance = *known_balances.entry(other_identity).or_insert(balance);
                            if already_seen_balance != balance {
                                return false;
                            }
                            if remaining_balances.remove_item(&balance).is_none() {
                                // There should have been a balance in our initial set, it's not there
                                return false;
                            }
                        } else {
                            // This identity did not have a balance, this should not happen
                            return false;
                        }
                    }
                    if remaining_balances.len() != 0 {
                        // we should have consumed all balances
                        return false;
                    }
                }

                known_balances.keys().cloned().collect::<HashSet<_>>() == net.identities()
            }

            // fn test_transfer(initial_balances: Vec<Money>, from_idx: usize, to_idx: usize, amount: Money) -> bool {
            //     let mut net = Net::new(&balances);
            //     let identities: Vec<Identity> = net.identities().into_iter().collect();
            //     let from = *identities[from_idx % identities.len()];
            //     let to = *identities[to_idx % identities.len()];
    //
            //     assert_eq!(net.read_balance_from_perspective_of_proc(32, 32), 1000);
            //     assert_eq!(net.read_balance_from_perspective_of_proc(91, 91), 0);
    //
            //     net.transfer(32, 32, 91, 1000);
    //
            //     assert_eq!(net.read_balance_from_perspective_of_proc(32, 32), 0);
            //     assert_eq!(net.read_balance_from_perspective_of_proc(91, 91), 1000);
            // }
        //
        //        #[test]
        //        fn test_double_spend() {
        //            let mut net = Net::default();
        //
        //            net.add_proc(32, 1000);
        //            net.add_proc(91, 0);
        //            net.add_proc(54, 0);
        //
        //            assert_eq!(net.read_balance_from_perspective_of_proc(32, 32), 1000);
        //            assert_eq!(net.read_balance_from_perspective_of_proc(91, 91), 0);
        //            assert_eq!(net.read_balance_from_perspective_of_proc(54, 54), 0);
        //
        //            net.step_until_done(vec![Cmd::BroadcastMsg {
        //                from: 32,
        //                msg: Msg {
        //                    op: Transfer {
        //                        from: 32,
        //                        to: 91,
        //                        amount: 1000,
        //                        deps: BTreeSet::new(),
        //                    },
        //                    source_version: Dot::new(32, 1),
        //                },
        //            }]);
        //
        //            assert_eq!(net.read_balance_from_perspective_of_proc(32, 32), 0);
        //            assert_eq!(net.read_balance_from_perspective_of_proc(91, 91), 1000);
        //            assert_eq!(net.read_balance_from_perspective_of_proc(54, 54), 0);
        //
        //            net.step_until_done(vec![Cmd::BroadcastMsg {
        //                from: 32,
        //                msg: Msg {
        //                    op: Transfer {
        //                        from: 32,
        //                        to: 54,
        //                        amount: 1000,
        //                        deps: BTreeSet::new(),
        //                    },
        //                    source_version: Dot::new(32, 1),
        //                },
        //            }]);
        //
        //            // Verify double spend was caught
        //            assert_eq!(net.read_balance_from_perspective_of_proc(32, 32), 0);
        //            assert_eq!(net.read_balance_from_perspective_of_proc(91, 91), 1000);
        //            assert_eq!(net.read_balance_from_perspective_of_proc(54, 54), 0);
        //        }
        //
        //        #[test]
        //        fn test_causal_dependancy() {
        //            let mut net = Net::default();
        //
        //            net.add_proc(32, 1000);
        //            net.add_proc(91, 1000);
        //            net.add_proc(54, 1000);
        //            net.add_proc(16, 1000);
        //
        //            assert_eq!(net.read_balance_from_perspective_of_proc(32, 32), 1000);
        //            assert_eq!(net.read_balance_from_perspective_of_proc(91, 91), 1000);
        //            assert_eq!(net.read_balance_from_perspective_of_proc(54, 54), 1000);
        //            assert_eq!(net.read_balance_from_perspective_of_proc(16, 16), 1000);
        //
        //            // T0:  32 -> 91
        //            net.transfer(32, 32, 91, 500);
        //
        //            // T1: 32 -> 54
        //            net.transfer(32, 32, 54, 500);
        //
        //            // T2: 91 -> 16
        //            net.transfer(91, 91, 16, 1500);
        //
        //            assert_eq!(net.read_balance_from_perspective_of_proc(32, 32), 0);
        //            assert_eq!(net.read_balance_from_perspective_of_proc(91, 91), 0);
        //            assert_eq!(net.read_balance_from_perspective_of_proc(54, 54), 1500);
        //            assert_eq!(net.read_balance_from_perspective_of_proc(16, 16), 2500);
        //        }
            }
}
