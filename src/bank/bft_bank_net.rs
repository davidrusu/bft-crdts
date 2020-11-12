use crate::actor::Actor;
use crate::bank::bft_bank::{Bank, Money, Op};
use crate::deterministic_secure_broadcast::Packet;
use crate::net::Net;

impl Net<Bank> {
    pub fn find_actor_with_balance(&self, balance: Money) -> Option<Actor> {
        self.actors()
            .iter()
            .cloned()
            .find(|a| self.balance_from_pov_of_proc(a, a).unwrap() == balance)
    }

    pub fn balance_from_pov_of_proc(&self, pov: &Actor, account: &Actor) -> Option<Money> {
        self.on_proc(pov, |p| p.read_state(|bank| bank.balance(account)))
    }

    pub fn open_account(
        &self,
        initiating_proc: Actor,
        bank_owner: Actor,
        initial_balance: Money,
    ) -> Option<Vec<Packet<Op>>> {
        self.on_proc(&initiating_proc, |p| {
            p.exec_algo_op(|bank| Some(bank.open_account(bank_owner, initial_balance)))
        })
    }

    pub fn transfer(
        &self,
        initiating_proc: Actor,
        from: Actor,
        to: Actor,
        amount: Money,
    ) -> Option<Vec<Packet<Op>>> {
        self.on_proc(&initiating_proc, |p| {
            p.exec_algo_op(|bank| bank.transfer(from, to, amount))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crdts::quickcheck::{quickcheck, TestResult};

    fn bootstrap_network(net: &mut Net<Bank>, balances: Vec<Money>) {
        let mut balance_iter = balances.into_iter();
        let genesis_balance = balance_iter.next().unwrap();
        let genesis_actor = net.initialize_proc();
        net.on_proc_mut(&genesis_actor, |p| p.trust_peer(genesis_actor))
            .unwrap();
        net.run_packets_to_completion(
            net.open_account(genesis_actor, genesis_actor, genesis_balance)
                .unwrap(),
        );

        for balance in balance_iter {
            let actor = net.initialize_proc();
            net.on_proc_mut(&actor, |p| p.trust_peer(genesis_actor));
            net.anti_entropy();
            net.run_packets_to_completion(net.on_proc(&actor, |p| p.request_membership()).unwrap());
            assert!(net.members_are_in_agreement());
            assert_eq!(net.count_invalid_packets(), 0);

            // TODO: add a test where the initiating actor is different from hte owner account
            net.run_packets_to_completion(net.open_account(actor, actor, balance).unwrap());
            assert!(net.members_are_in_agreement());
            assert_eq!(net.count_invalid_packets(), 0);
        }

        assert!(net.members_are_in_agreement());
        assert_eq!(net.count_invalid_packets(), 0);
    }

    quickcheck! {
        fn there_is_agreement_on_initial_balances(balances: Vec<Money>) -> TestResult {
            if balances.is_empty() || balances.len() > 7 {
                // for the sake of time/computation, it's unlikely that we will have novel interesting behaviour with more procs.
                return TestResult::discard()
            }

            let mut net = Net::new();
            bootstrap_network(&mut net, balances.clone());

            // make sure that all balances in the network appear in the initial list of balances
            // and all balances in the initial list appear in the network (full actor <-> balance correspondance check)
            for actor in net.actors() {
                let mut remaining_balances = balances.clone();

                for other_actor in net.actors() {
                    let balance = net.balance_from_pov_of_proc(&actor, &other_actor).unwrap();

                    let removed_balance = remaining_balances
                        .iter()
                        .position(|x| *x == balance)
                        .map(|i| remaining_balances.remove(i))
                        .unwrap();
                    assert_eq!(removed_balance, balance);
                }
                assert_eq!(remaining_balances, vec![]);
            }

            TestResult::passed()
        }

        fn properties_of_a_single_transfer(balances: Vec<Money>, initiator_idx: usize, from_idx: usize, to_idx: usize, amount: Money) -> TestResult {
            if balances.is_empty() || balances.len() > 7 {
                return TestResult::discard()
            }

            let mut net = Net::new();
            bootstrap_network(&mut net, balances.clone());

            let actors: Vec<Actor> = net.actors().into_iter().collect();

            let initiator = actors[initiator_idx % actors.len()];
            let from = actors[from_idx % actors.len()];
            let to = actors[to_idx % actors.len()];

            let initial_from_balance = net.balance_from_pov_of_proc(&initiator, &from).unwrap();
            let initial_to_balance = net.balance_from_pov_of_proc(&initiator, &to).unwrap();

            net.run_packets_to_completion(net.transfer(initiator, from, to, amount).unwrap());
            assert!(net.members_are_in_agreement());

            let final_from_balance = net.balance_from_pov_of_proc(&initiator, &from).unwrap();
            let final_to_balance = net.balance_from_pov_of_proc(&initiator, &to).unwrap();

            if initiator != from || initial_from_balance < amount {
                // The network should have rejected these transfers on the grounds of initiator being an imposters or not enough funds
                assert_eq!(final_from_balance, initial_from_balance);
                assert_eq!(final_to_balance, initial_to_balance);
            } else if initial_from_balance >= amount {
                // transfer should have succeeded
                if from != to {
                    // From and to are different accounts, there should be a change in balance that matches the transfer amount

                    let from_balance_abs_delta = initial_from_balance - final_from_balance; // inverted because the delta is neg.
                    let to_balance_abs_delta = final_to_balance - initial_to_balance;

                    assert_eq!(from_balance_abs_delta, amount);
                    assert_eq!(from_balance_abs_delta, to_balance_abs_delta);
                } else {
                    // From and to are the same account, there should be no change in the account balance
                    assert_eq!(final_from_balance, initial_from_balance);
                    assert_eq!(final_to_balance, initial_to_balance);
                }
            } else {
                panic!("Unknown state");
            }

            TestResult::passed()
        }


        fn protection_against_double_spend(balances: Vec<Money>, packet_interleave: Vec<usize>) -> TestResult {
            if balances.len() < 3 || balances.len() > 7 || packet_interleave.is_empty() {
                return TestResult::discard();
            }

            let mut net = Net::new();
            bootstrap_network(&mut net, balances.clone());

            let actors: Vec<_> = net.actors().into_iter().collect();
            let a = actors[0];
            let b = actors[1];
            let c = actors[2];

            let a_init_balance = net.balance_from_pov_of_proc(&a, &a).unwrap();
            let b_init_balance = net.balance_from_pov_of_proc(&b, &b).unwrap();
            let c_init_balance = net.balance_from_pov_of_proc(&c, &c).unwrap();

            let mut first_broadcast_packets = net.transfer(a, a, b, a_init_balance).unwrap();
            let mut second_broadcast_packets = net.transfer(a, a, c, a_init_balance).unwrap();

            let mut packet_number = 0;
            let mut packet_queue: Vec<Packet<Op>> = Vec::new();

            // Interleave the initial broadcast packets
            while !first_broadcast_packets.is_empty() || !second_broadcast_packets.is_empty() {
                let packet_position = packet_interleave[packet_number % packet_interleave.len()];
                let packet = if packet_position % 2 == 0 {
                    first_broadcast_packets.pop().unwrap_or_else(|| second_broadcast_packets.pop().unwrap())
                } else {
                    second_broadcast_packets.pop().unwrap_or_else(|| first_broadcast_packets.pop().unwrap())
                };
                packet_queue.push(packet);
                packet_number += 1;
            }

            while let Some(packet) = packet_queue.pop() {
                let new_packets = net.deliver_packet(packet);

                for packet in new_packets {
                    let packet_position = packet_interleave[packet_number % packet_interleave.len()];
                    let packet_position_capped = packet_position % packet_queue.len().max(1);
                    packet_queue.insert(packet_position_capped, packet);
                    packet_number += 1;
                }
            }

            assert!(net.members_are_in_agreement());

            let a_final_balance = net.balance_from_pov_of_proc(&a, &a).unwrap();
            let b_final_balance = net.balance_from_pov_of_proc(&b, &b).unwrap();
            let c_final_balance = net.balance_from_pov_of_proc(&c, &c).unwrap();
            let a_delta = a_init_balance - a_final_balance; // rev. since we are withdrawing from a
            let b_delta = b_final_balance - b_init_balance;
            let c_delta = c_final_balance - c_init_balance;

            // two cases:
            // 1. Exactly one of the transfers should have gone through, not both
            // 2. No transactions go through
            if a_delta != 0 {
                // case 1. exactly one transfer went through
                assert!((b_delta == a_init_balance && c_delta == 0) || (b_delta == 0 && c_delta == a_init_balance));
            } else {
                // case 2. no change
                assert_eq!(a_delta, 0);
                assert_eq!(b_delta, 0);
                assert_eq!(c_delta, 0);
            }

            TestResult::passed()
        }
    }

    #[test]
    fn there_is_agreement_on_initial_balances_qc1() {
        // Quickcheck found some problems with an earlier version of the BFT onboarding logic.
        // This is a direct copy of the quickcheck tests, together with the failing test vector.
        let balances = vec![0, 0];

        let mut net = Net::new();
        bootstrap_network(&mut net, balances.clone());

        // make sure that all balances in the network appear in the initial list of balances
        // and all balances in the initial list appear in the network (full actor <-> balance correspondance check)
        for actor in net.actors() {
            let mut remaining_balances = balances.clone();

            for other_actor in net.actors() {
                let balance = net.balance_from_pov_of_proc(&actor, &other_actor).unwrap();

                // This balance should have been in our initial set
                let removed_balance = remaining_balances
                    .iter()
                    .position(|x| *x == balance)
                    .map(|i| remaining_balances.remove(i))
                    .unwrap();
                assert_eq!(removed_balance, balance);
            }

            assert_eq!(remaining_balances.len(), 0);
        }

        assert_eq!(net.n_packets, 13);
    }

    #[test]
    fn test_transfer_is_actually_moving_money_qc1() {
        let balances = vec![0, 9];
        let mut net = Net::new();
        bootstrap_network(&mut net, balances.clone());

        let initiator = net.find_actor_with_balance(9).unwrap();
        let from = initiator;
        let to = net.find_actor_with_balance(0).unwrap();
        let amount = 9;

        let initial_from_balance = net.balance_from_pov_of_proc(&initiator, &from).unwrap();
        let initial_to_balance = net.balance_from_pov_of_proc(&initiator, &to).unwrap();

        assert_eq!(initial_from_balance, 9);
        assert_eq!(initial_to_balance, 0);

        let mut packets = net.transfer(initiator, from, to, amount).unwrap();

        while let Some(packet) = packets.pop() {
            packets.extend(net.deliver_packet(packet));
        }

        assert!(net.members_are_in_agreement());

        let final_from_balance = net.balance_from_pov_of_proc(&initiator, &from).unwrap();
        let final_to_balance = net.balance_from_pov_of_proc(&initiator, &to).unwrap();

        let from_balance_abs_delta = initial_from_balance - final_from_balance; // inverted because the delta is neg.
        let to_balance_abs_delta = final_to_balance - initial_to_balance;

        assert_eq!(from_balance_abs_delta, amount);
        assert_eq!(from_balance_abs_delta, to_balance_abs_delta);

        assert_eq!(net.n_packets, 19);
    }

    #[test]
    fn test_causal_dependancy() {
        let balances = vec![1000, 1000, 1000, 1000];
        let mut net = Net::new();
        bootstrap_network(&mut net, balances.clone());

        let actors: Vec<_> = net.actors().into_iter().collect();
        let a = actors[0];
        let b = actors[1];
        let c = actors[2];
        let d = actors[3];

        // T0:  a -> b
        let packets = net.transfer(a, a, b, 500).unwrap();
        net.run_packets_to_completion(packets);
        assert!(net.members_are_in_agreement());
        assert_eq!(net.balance_from_pov_of_proc(&a, &a), Some(500));
        assert_eq!(net.balance_from_pov_of_proc(&b, &b), Some(1500));
        assert_eq!(net.balance_from_pov_of_proc(&c, &c), Some(1000));
        assert_eq!(net.balance_from_pov_of_proc(&d, &d), Some(1000));

        // T1: a -> c
        let packets = net.transfer(a, a, c, 500).unwrap();
        net.run_packets_to_completion(packets);
        assert!(net.members_are_in_agreement());
        assert_eq!(net.balance_from_pov_of_proc(&a, &a), Some(0));
        assert_eq!(net.balance_from_pov_of_proc(&b, &b), Some(1500));
        assert_eq!(net.balance_from_pov_of_proc(&c, &c), Some(1500));
        assert_eq!(net.balance_from_pov_of_proc(&d, &d), Some(1000));

        // T2: b -> d
        let packets = net.transfer(b, b, d, 1500).unwrap();
        net.run_packets_to_completion(packets);
        assert!(net.members_are_in_agreement());
        assert_eq!(net.balance_from_pov_of_proc(&a, &a), Some(0));
        assert_eq!(net.balance_from_pov_of_proc(&b, &b), Some(0));
        assert_eq!(net.balance_from_pov_of_proc(&c, &c), Some(1500));
        assert_eq!(net.balance_from_pov_of_proc(&d, &d), Some(2500));

        assert_eq!(net.n_packets, 87);
    }

    #[test]
    fn test_double_spend_qc2() {
        let balances = vec![0, 0, 0];
        let mut net = Net::new();
        bootstrap_network(&mut net, balances.clone());

        let actors: Vec<_> = net.actors().into_iter().collect();
        let a = actors[0];
        let b = actors[1];
        let c = actors[2];

        let a_init_balance = net.balance_from_pov_of_proc(&a, &a).unwrap();
        let b_init_balance = net.balance_from_pov_of_proc(&b, &b).unwrap();
        let c_init_balance = net.balance_from_pov_of_proc(&c, &c).unwrap();

        let mut packet_queue: Vec<Packet<Op>> = Vec::new();
        packet_queue.extend(net.transfer(a, a, b, a_init_balance).unwrap());
        packet_queue.extend(net.transfer(a, a, c, a_init_balance).unwrap());

        while let Some(packet) = packet_queue.pop() {
            for packet in net.deliver_packet(packet) {
                packet_queue.insert(0, packet);
            }
        }

        assert!(net.members_are_in_agreement());

        let a_final_balance = net.balance_from_pov_of_proc(&a, &a).unwrap();
        let b_final_balance = net.balance_from_pov_of_proc(&b, &b).unwrap();
        let c_final_balance = net.balance_from_pov_of_proc(&c, &c).unwrap();
        let b_delta = b_final_balance - b_init_balance;
        let c_delta = c_final_balance - c_init_balance;

        // Exactly one of the transfers should have gone through, not both
        assert_eq!(a_final_balance, 0);
        assert!(
            (b_delta == a_init_balance && c_delta == 0)
                || (b_delta == 0 && c_delta == a_init_balance)
        );
        assert_eq!(net.n_packets, 41);
    }

    #[test]
    fn test_attempt_to_double_spend_with_even_number_of_procs_qc3() {
        // Found by quickcheck. When we attempt to double spend and distribute
        // requests for validation evenly between procs, the network will not
        // execute any transaction.

        let balances = vec![2, 3, 4, 1];
        let mut net = Net::new();
        bootstrap_network(&mut net, balances.clone());

        let a = net.find_actor_with_balance(1).unwrap();
        let b = net.find_actor_with_balance(2).unwrap();
        let c = net.find_actor_with_balance(3).unwrap();

        let mut first_broadcast_packets = net.transfer(a, a, b, 1).unwrap();
        let mut second_broadcast_packets = net.transfer(a, a, c, 1).unwrap();

        let mut packet_number = 0;
        let mut packet_queue: Vec<Packet<Op>> = Vec::new();
        let packet_interleave = vec![0, 0, 15, 9, 67, 99];

        // Interleave the initial broadcast packets
        while !first_broadcast_packets.is_empty() || !second_broadcast_packets.is_empty() {
            let packet = if packet_interleave[packet_number % packet_interleave.len()] % 2 == 0 {
                first_broadcast_packets
                    .pop()
                    .unwrap_or_else(|| second_broadcast_packets.pop().unwrap())
            } else {
                second_broadcast_packets
                    .pop()
                    .unwrap_or_else(|| first_broadcast_packets.pop().unwrap())
            };
            packet_queue.push(packet);
            packet_number += 1;
        }

        while let Some(packet) = packet_queue.pop() {
            let new_packets = net.deliver_packet(packet);

            for packet in new_packets {
                let packet_position = packet_interleave[packet_number % packet_interleave.len()]
                    % packet_queue.len().max(1);
                packet_queue.insert(packet_position, packet);
            }
        }

        assert!(net.members_are_in_agreement());

        let a_final_balance = net.balance_from_pov_of_proc(&a, &a).unwrap();
        let b_final_balance = net.balance_from_pov_of_proc(&b, &b).unwrap();
        let c_final_balance = net.balance_from_pov_of_proc(&c, &c).unwrap();

        assert_eq!(a_final_balance, 1);
        assert_eq!(b_final_balance, 2);
        assert_eq!(c_final_balance, 3);

        assert_eq!(net.n_packets, 63);
    }
}
