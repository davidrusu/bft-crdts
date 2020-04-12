use std::collections::{HashMap, HashSet};

use crate::at2::bank::Money;
use crate::at2::deterministic_secure_broadcast::{Packet, SecureBroadcastProc};
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

    fn find_identity_with_balance(&self, balance: Money) -> Option<Identity> {
        self.identities()
            .iter()
            .cloned()
            .find(|i| self.balance_from_pov_of_proc(*i, *i).unwrap() == balance)
    }

    fn balance_from_pov_of_proc(&self, pov: Identity, account: Identity) -> Option<Money> {
        self.procs
            .iter()
            .find(|secure_p| secure_p.identity() == pov)
            .map(|secure_p| secure_p.read_state(|p| p.balance(account)))
    }

    fn transfer(
        &self,
        initiating_proc: Identity,
        from: Identity,
        to: Identity,
        amount: Money,
    ) -> Vec<Packet> {
        self.procs
            .iter()
            .find(|p| p.identity() == initiating_proc)
            .expect("[ERROR] invalid initiating_proc proc")
            .exec_bft_op(|p| p.transfer(from, to, amount))
    }

    fn deliver_packet(&mut self, packet: Packet) -> Vec<Packet> {
        println!("[NET] Delivering packet {}->{}", packet.source, packet.dest);
        self.procs
            .iter_mut()
            .find(|p| p.identity() == packet.dest)
            .map(|p| p.handle_packet(packet))
            .unwrap_or_default()
    }

    fn everyone_is_in_agreement(&self) -> bool {
        let mut balances_by_proc: HashMap<Identity, HashSet<Money>> = HashMap::new();

        for identity in self.identities() {
            for balance_identity in self.identities() {
                if let Some(balance) = self.balance_from_pov_of_proc(identity, balance_identity) {
                    balances_by_proc
                        .entry(balance_identity)
                        .or_default()
                        .insert(balance);
                } else {
                    // This identity did not exist
                    return false;
                }
            }
        }

        for (identity, balances) in balances_by_proc {
            if balances.len() != 1 {
                println!(
                    "{} has a disagreement on it's balance: {:?}",
                    identity, balances
                );
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crdts::quickcheck::{quickcheck, TestResult};

    quickcheck! {
        fn there_is_agreement_on_initial_balances(balances: Vec<Money>) -> bool {
            let net = Net::new(&balances);
            if !net.everyone_is_in_agreement() {
                return false
            }

            // make sure that all balances in the network appear in the initial list of balances
            // and all balances in the initial list appear in the network (full identity <-> balance correspondance check)
            for identity in net.identities() {
                let mut remaining_balances = balances.clone();

                for other_identity in net.identities() {
                    if let Some(balance) = net.balance_from_pov_of_proc(identity, other_identity) {
                        if remaining_balances.remove_item(&balance).is_none() {
                            // This balance should have been in our initial set
                            return false;
                        }
                    } else {
                        // This identity did not exist
                        return false;
                    }
                }

                if remaining_balances.len() != 0 {
                    // we should have consumed all balances
                    return false;
                }
            }

            true
        }

        fn properties_of_a_single_transfer(balances: Vec<Money>, initiator_idx: usize, from_idx: usize, to_idx: usize, amount: Money) -> TestResult {
            if balances.len() == 0 {
                return TestResult::discard()
            }

            let mut net = Net::new(&balances);
            let identities: Vec<Identity> = net.identities().into_iter().collect();

            let initiator = identities[initiator_idx % identities.len()];
            let from = identities[from_idx % identities.len()];
            let to = identities[to_idx % identities.len()];

            let initial_from_balance = net.balance_from_pov_of_proc(initiator, from).unwrap();
            let initial_to_balance = net.balance_from_pov_of_proc(initiator, to).unwrap();

            let mut packets = net.transfer(initiator, from, to, amount);

            // TODO: new test, ensure the number of packets processed is bounded and deterministic
            while let Some(packet) = packets.pop() {
                packets.extend(net.deliver_packet(packet));
            }

            assert!(net.everyone_is_in_agreement());

            let final_from_balance = net.balance_from_pov_of_proc(initiator, from).unwrap();
            let final_to_balance = net.balance_from_pov_of_proc(initiator, to).unwrap();

            // println!("[TEST] balance changes: from {} -> {}; to {} -> {}", initial_from_balance, final_from_balance, initial_to_balance, final_to_balance);

            if initiator != from {
                //println!("[TEST] initiator is creating a transfer on behalf of another account, the network should reject this");
                TestResult::from_bool(final_from_balance == initial_from_balance && final_to_balance == initial_to_balance)
            } else if initial_from_balance >= amount {
                //println!("[TEST] from account had enought money for the transfer");
                // transfer should have succeeded
                if from != to {
                    println!("[TEST] from and to are different accounts, there should be a change in balance that matches the transfer amount");
                    let from_balance_abs_delta = initial_from_balance - final_from_balance; // inverted because the delta is neg.
                    let to_balance_abs_delta = final_to_balance - initial_to_balance;
                    assert_eq!(from_balance_abs_delta, amount);
                    assert_eq!(from_balance_abs_delta, to_balance_abs_delta);
                    TestResult::from_bool(from_balance_abs_delta == amount && from_balance_abs_delta == to_balance_abs_delta)
                } else {
                    println!("[TEST] from and to are the same account, there should be no change in the account balance");
                    TestResult::from_bool(final_from_balance == initial_from_balance) // from == to; no need to check both
                }
            } else if initial_from_balance < amount {
                // println!("[TEST] from account did not have enough money for the transfer");
                // transfer should have failed, balances should have remained unchanged
                TestResult::from_bool(final_from_balance == initial_from_balance && final_to_balance == initial_to_balance)
            } else {
                panic!("Unknown state");
            }
        }

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
    }

    #[test]
    fn test_transfer_is_actually_moving_money_qc1() {
        let mut net = Net::new(&[0, 9]);

        let initiator = net.find_identity_with_balance(9).unwrap();
        let from = initiator;
        let to = net.find_identity_with_balance(0).unwrap();
        let amount = 9;

        let initial_from_balance = net.balance_from_pov_of_proc(initiator, from).unwrap();
        let initial_to_balance = net.balance_from_pov_of_proc(initiator, to).unwrap();

        assert_eq!(initial_from_balance, 9);
        assert_eq!(initial_to_balance, 0);

        let mut packets = net.transfer(initiator, from, to, amount);

        while let Some(packet) = packets.pop() {
            packets.extend(net.deliver_packet(packet));
        }

        assert!(net.everyone_is_in_agreement());

        let final_from_balance = net.balance_from_pov_of_proc(initiator, from).unwrap();
        let final_to_balance = net.balance_from_pov_of_proc(initiator, to).unwrap();

        let from_balance_abs_delta = initial_from_balance - final_from_balance; // inverted because the delta is neg.
        let to_balance_abs_delta = final_to_balance - initial_to_balance;

        assert_eq!(from_balance_abs_delta, amount);
        assert_eq!(from_balance_abs_delta, to_balance_abs_delta);
    }

    #[test]
    fn test_causal_dependancy() {
        let mut net = Net::new(&[1000, 1000, 1000, 1000]);

        let identities: Vec<_> = net.identities().into_iter().collect();
        let a = identities[0];
        let b = identities[1];
        let c = identities[2];
        let d = identities[3];

        let mut packets = Vec::new();
        // T0:  a -> b
        packets.extend(net.transfer(a, a, b, 500));

        while let Some(packet) = packets.pop() {
            packets.extend(net.deliver_packet(packet));
        }
        assert!(net.everyone_is_in_agreement());

        // T1: a -> c
        packets.extend(net.transfer(a, a, c, 500));

        while let Some(packet) = packets.pop() {
            packets.extend(net.deliver_packet(packet));
        }
        assert!(net.everyone_is_in_agreement());

        // T2: b -> d
        packets.extend(net.transfer(b, b, d, 1500));

        while let Some(packet) = packets.pop() {
            packets.extend(net.deliver_packet(packet));
        }
        assert!(net.everyone_is_in_agreement());

        assert_eq!(net.balance_from_pov_of_proc(a, a), Some(0));
        assert_eq!(net.balance_from_pov_of_proc(b, b), Some(0));
        assert_eq!(net.balance_from_pov_of_proc(c, c), Some(1500));
        assert_eq!(net.balance_from_pov_of_proc(d, d), Some(2500));
    }
}
