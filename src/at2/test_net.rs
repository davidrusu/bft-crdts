use std::collections::{HashMap, HashSet};

use crate::at2::bank::{Bank, Money, Op};
use crate::at2::deterministic_secure_broadcast::{Packet, SecureBroadcastProc};
use crate::at2::identity::Identity;

#[derive(Debug)]
struct Net {
    procs: Vec<SecureBroadcastProc<Bank>>, // Make this a Map<Identity, SecureBroadcastProc>
    n_packets: u64,
}

impl Net {
    fn new() -> Self {
        Self {
            procs: Vec::new(),
            n_packets: 0,
        }
    }

    fn members(&self) -> HashSet<Identity> {
        // the largest subset of procs that mutually see each other as peers
        self.procs
            .iter()
            .map(|proc| {
                proc.peers()
                    .iter()
                    .flat_map(|peer| self.proc_from_id(peer))
                    .filter(|peer_proc| peer_proc.peers().contains(&proc.identity()))
                    .map(|peer_proc| peer_proc.identity())
                    .collect::<HashSet<_>>()
            })
            .max_by_key(|members| members.len())
            .unwrap_or_default()
    }

    fn initialize_proc(&mut self) -> Identity {
        let proc = SecureBroadcastProc::new(self.members());
        let id = proc.identity();
        self.procs.push(proc);
        id
    }

    fn on_proc<V>(
        &self,
        id: &Identity,
        f: impl FnOnce(&SecureBroadcastProc<Bank>) -> V,
    ) -> Option<V> {
        self.proc_from_id(id).map(|p| f(p))
    }

    fn on_proc_mut<V>(
        &mut self,
        id: &Identity,
        f: impl FnOnce(&mut SecureBroadcastProc<Bank>) -> V,
    ) -> Option<V> {
        self.proc_from_id_mut(id).map(|p| f(p))
    }

    // TODO: inline these two methods if they continue to only be used by `on_proc*`
    fn proc_from_id(&self, id: &Identity) -> Option<&SecureBroadcastProc<Bank>> {
        self.procs
            .iter()
            .find(|secure_p| &secure_p.identity() == id)
    }

    fn proc_from_id_mut(&mut self, id: &Identity) -> Option<&mut SecureBroadcastProc<Bank>> {
        self.procs
            .iter_mut()
            .find(|secure_p| &secure_p.identity() == id)
    }

    fn anti_entropy(&mut self) {
        // TODO: this should be done through a message(packet) passing interface.
        println!("[TEST_NET] anti_entropy");

        // For each proc, collect the procs who considers this proc it's peer.
        let mut peer_reverse_index: HashMap<Identity, HashSet<Identity>> = HashMap::new();

        for proc in self.procs.iter() {
            for peer in proc.peers() {
                peer_reverse_index
                    .entry(peer)
                    .or_default()
                    .insert(proc.identity());
            }
        }

        for (proc_id, reverse_peers) in peer_reverse_index {
            // other procs that consider this proc a peer, will share there state with this proc
            for reverse_peer in reverse_peers {
                let source_peer_state = self.proc_from_id(&reverse_peer).unwrap().state();
                self.on_proc_mut(&proc_id, |p| p.sync_from(source_peer_state));
                println!("[TEST_NET] {} -> {}", reverse_peer, proc_id);
            }
        }
    }

    fn identities(&self) -> HashSet<Identity> {
        self.procs.iter().map(|p| p.identity()).collect()
    }

    fn find_identity_with_balance(&self, balance: Money) -> Option<Identity> {
        self.identities()
            .iter()
            .cloned()
            .find(|i| self.balance_from_pov_of_proc(i, i).unwrap() == balance)
    }

    fn balance_from_pov_of_proc(&self, pov: &Identity, account: &Identity) -> Option<Money> {
        self.on_proc(pov, |p| p.read_state(|bank| bank.balance(account)))
    }

    fn open_account(
        &self,
        initiating_proc: Identity,
        bank_owner: Identity,
        initial_balance: Money,
    ) -> Option<Vec<Packet<Op>>> {
        self.on_proc(&initiating_proc, |p| {
            p.exec_algo_op(|bank| Some(bank.open_account(bank_owner, initial_balance)))
        })
    }

    fn transfer(
        &self,
        initiating_proc: Identity,
        from: Identity,
        to: Identity,
        amount: Money,
    ) -> Option<Vec<Packet<Op>>> {
        self.on_proc(&initiating_proc, |p| {
            p.exec_algo_op(|bank| bank.transfer(from, to, amount))
        })
    }

    fn deliver_packet(&mut self, packet: Packet<Op>) -> Vec<Packet<Op>> {
        println!("[NET] packet {}->{}", packet.source, packet.dest);
        self.n_packets += 1;
        self.on_proc_mut(&packet.dest.clone(), |p| p.handle_packet(packet))
            .unwrap_or_default()
    }

    fn everyone_is_in_agreement(&self) -> bool {
        let mut member_states_iter = self
            .members()
            .into_iter()
            .flat_map(|id| self.proc_from_id(&id))
            .map(|p| p.state());

        let reference_state = if let Some(state) = member_states_iter.next() {
            member_states_iter.all(|s| s == reference_state)
        } else {
            true
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crdts::quickcheck::{quickcheck, TestResult};

    quickcheck! {
        fn there_is_agreement_on_initial_balances(balances: Vec<Money>) -> bool {
            let mut net = Net::new();
            for balance in balances.iter().cloned() {
                let identity = net.initialize_proc();

                let mut packets = net.on_proc(&identity, |p| p.request_membership()).unwrap();
                while let Some(packet) = packets.pop() {
                    packets.extend(net.deliver_packet(packet));
                }

                net.anti_entropy();

                // TODO: add a test where the initiating identity is different from hte owner account
                let mut packets = net.open_account(identity, identity, balance).unwrap();
                while let Some(packet) = packets.pop() {
                    packets.extend(net.deliver_packet(packet));
                }
            }

            if !net.everyone_is_in_agreement() {
                return false
            }

            // make sure that all balances in the network appear in the initial list of balances
            // and all balances in the initial list appear in the network (full identity <-> balance correspondance check)
            for identity in net.identities() {
                let mut remaining_balances = balances.clone();

                for other_identity in net.identities() {
                    if let Some(balance) = net.balance_from_pov_of_proc(&identity, &other_identity) {
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


            let mut net = Net::new();
            for balance in balances.iter().cloned() {
                let identity = net.initialize_proc();

                let mut packets = net.on_proc(&identity, |p| p.request_membership()).unwrap();
                while let Some(packet) = packets.pop() {
                    packets.extend(net.deliver_packet(packet));
                }

                net.anti_entropy();

                // TODO: add a test where the initiating identity is different from hte owner account
                let mut packets = net.open_account(identity, identity, balance).unwrap();
                while let Some(packet) = packets.pop() {
                    packets.extend(net.deliver_packet(packet));
                }
            }

            let identities: Vec<Identity> = net.identities().into_iter().collect();

            let initiator = identities[initiator_idx % identities.len()];
            let from = identities[from_idx % identities.len()];
            let to = identities[to_idx % identities.len()];

            let initial_from_balance = net.balance_from_pov_of_proc(&initiator, &from).unwrap();
            let initial_to_balance = net.balance_from_pov_of_proc(&initiator, &to).unwrap();

            let mut packets = net.transfer(initiator, from, to, amount).unwrap();

            // TODO: new test, ensure the number of packets processed is bounded and deterministic
            while let Some(packet) = packets.pop() {
                packets.extend(net.deliver_packet(packet));
            }
            assert!(net.everyone_is_in_agreement());

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
            if balances.len() < 3 || packet_interleave.len() == 0{
                return TestResult::discard();
            }

            let mut net = Net::new();
            for balance in balances.iter().cloned() {
                let identity = net.initialize_proc();

                let mut packets = net.on_proc(&identity, |p| p.request_membership()).unwrap();
                while let Some(packet) = packets.pop() {
                    packets.extend(net.deliver_packet(packet));
                }

                net.anti_entropy();

                // TODO: add a test where the initiating identity is different from hte owner account
                let mut packets = net.open_account(identity, identity, balance).unwrap();
                while let Some(packet) = packets.pop() {
                    packets.extend(net.deliver_packet(packet));
                }
            }

            let identities: Vec<_> = net.identities().into_iter().collect();
            let a = identities[0];
            let b = identities[1];
            let c = identities[2];

            let a_init_balance = net.balance_from_pov_of_proc(&a, &a).unwrap();
            let b_init_balance = net.balance_from_pov_of_proc(&b, &b).unwrap();
            let c_init_balance = net.balance_from_pov_of_proc(&c, &c).unwrap();

            let mut first_broadcast_packets = net.transfer(a, a, b, a_init_balance).unwrap();
            let mut second_broadcast_packets = net.transfer(a, a, c, a_init_balance).unwrap();

            let mut packet_number = 0;
            let mut packet_queue: Vec<Packet<Op>> = Vec::new();

            // Interleave the initial broadcast packets
            while first_broadcast_packets.len() > 0 || second_broadcast_packets.len() > 0 {
                let packet = if packet_interleave[packet_number % packet_interleave.len()] % 2 == 0 {
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
                    let packet_position = packet_interleave[packet_number % packet_interleave.len()] % packet_queue.len().max(1);
                    packet_queue.insert(packet_position, packet);
                    packet_number += 1;
                }
            }

            assert!(net.everyone_is_in_agreement());

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
        for balance in balances.iter().cloned() {
            let identity = net.initialize_proc();

            let mut packets = net.on_proc(&identity, |p| p.request_membership()).unwrap();
            while let Some(packet) = packets.pop() {
                packets.extend(net.deliver_packet(packet));
            }

            net.anti_entropy();

            // TODO: add a test where the initiating identity is different from hte owner account
            let mut packets = net.open_account(identity, identity, balance).unwrap();
            while let Some(packet) = packets.pop() {
                packets.extend(net.deliver_packet(packet));
            }
        }

        assert!(net.everyone_is_in_agreement());

        // make sure that all balances in the network appear in the initial list of balances
        // and all balances in the initial list appear in the network (full identity <-> balance correspondance check)
        for identity in net.identities() {
            let mut remaining_balances = balances.clone();

            for other_identity in net.identities() {
                let balance = net
                    .balance_from_pov_of_proc(&identity, &other_identity)
                    .unwrap();
                // This balance should have been in our initial set
                assert!(remaining_balances.remove_item(&balance).is_some());
            }

            assert_eq!(remaining_balances.len(), 0);
        }

        assert_eq!(net.n_packets, 13);
    }

    #[test]
    fn test_transfer_is_actually_moving_money_qc1() {
        let mut net = Net::new();
        for balance in vec![0, 9] {
            let identity = net.initialize_proc();

            let mut packets = net.on_proc(&identity, |p| p.request_membership()).unwrap();
            while let Some(packet) = packets.pop() {
                packets.extend(net.deliver_packet(packet));
            }

            net.anti_entropy();

            // TODO: add a test where the initiating identity is different from hte owner account
            let mut packets = net.open_account(identity, identity, balance).unwrap();
            while let Some(packet) = packets.pop() {
                packets.extend(net.deliver_packet(packet));
            }
        }

        let initiator = net.find_identity_with_balance(9).unwrap();
        let from = initiator;
        let to = net.find_identity_with_balance(0).unwrap();
        let amount = 9;

        let initial_from_balance = net.balance_from_pov_of_proc(&initiator, &from).unwrap();
        let initial_to_balance = net.balance_from_pov_of_proc(&initiator, &to).unwrap();

        assert_eq!(initial_from_balance, 9);
        assert_eq!(initial_to_balance, 0);

        let mut packets = net.transfer(initiator, from, to, amount).unwrap();

        while let Some(packet) = packets.pop() {
            packets.extend(net.deliver_packet(packet));
        }

        assert!(net.everyone_is_in_agreement());

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
        let mut net = Net::new();
        for balance in vec![1000, 1000, 1000, 1000] {
            let identity = net.initialize_proc();

            let mut packets = net.on_proc(&identity, |p| p.request_membership()).unwrap();
            while let Some(packet) = packets.pop() {
                packets.extend(net.deliver_packet(packet));
            }

            net.anti_entropy();

            // TODO: add a test where the initiating identity is different from hte owner account
            let mut packets = net.open_account(identity, identity, balance).unwrap();
            while let Some(packet) = packets.pop() {
                packets.extend(net.deliver_packet(packet));
            }
        }

        let identities: Vec<_> = net.identities().into_iter().collect();
        let a = identities[0];
        let b = identities[1];
        let c = identities[2];
        let d = identities[3];

        // T0:  a -> b
        let mut packets = net.transfer(a, a, b, 500).unwrap();
        while let Some(packet) = packets.pop() {
            packets.extend(net.deliver_packet(packet));
        }
        assert!(net.everyone_is_in_agreement());
        assert_eq!(net.balance_from_pov_of_proc(&a, &a), Some(500));
        assert_eq!(net.balance_from_pov_of_proc(&b, &b), Some(1500));
        assert_eq!(net.balance_from_pov_of_proc(&c, &c), Some(1000));
        assert_eq!(net.balance_from_pov_of_proc(&d, &d), Some(1000));

        // T1: a -> c
        let mut packets = net.transfer(a, a, c, 500).unwrap();
        while let Some(packet) = packets.pop() {
            packets.extend(net.deliver_packet(packet));
        }
        assert!(net.everyone_is_in_agreement());
        assert_eq!(net.balance_from_pov_of_proc(&a, &a), Some(0));
        assert_eq!(net.balance_from_pov_of_proc(&b, &b), Some(1500));
        assert_eq!(net.balance_from_pov_of_proc(&c, &c), Some(1500));
        assert_eq!(net.balance_from_pov_of_proc(&d, &d), Some(1000));

        // T2: b -> d
        let mut packets = net.transfer(b, b, d, 1500).unwrap();
        while let Some(packet) = packets.pop() {
            packets.extend(net.deliver_packet(packet));
        }
        assert!(net.everyone_is_in_agreement());
        assert_eq!(net.balance_from_pov_of_proc(&a, &a), Some(0));
        assert_eq!(net.balance_from_pov_of_proc(&b, &b), Some(0));
        assert_eq!(net.balance_from_pov_of_proc(&c, &c), Some(1500));
        assert_eq!(net.balance_from_pov_of_proc(&d, &d), Some(2500));

        assert_eq!(net.n_packets, 85);
    }

    #[test]
    fn test_double_spend_qc2() {
        let mut net = Net::new();
        for balance in vec![0, 0, 0] {
            let identity = net.initialize_proc();

            let mut packets = net.on_proc(&identity, |p| p.request_membership()).unwrap();
            while let Some(packet) = packets.pop() {
                packets.extend(net.deliver_packet(packet));
            }

            net.anti_entropy();

            // TODO: add a test where the initiating identity is different from hte owner account
            let mut packets = net.open_account(identity, identity, balance).unwrap();
            while let Some(packet) = packets.pop() {
                packets.extend(net.deliver_packet(packet));
            }
        }

        let identities: Vec<_> = net.identities().into_iter().collect();
        let a = identities[0];
        let b = identities[1];
        let c = identities[2];

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

        assert!(net.everyone_is_in_agreement());

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
        assert_eq!(net.n_packets, 40);
    }

    #[test]
    fn test_attempt_to_double_spend_with_even_number_of_procs_qc3() {
        // Found by quickcheck. When we attempt to double spend and distribute
        // requests for validation evenly between procs, the network will not
        // execute any transaction.

        let mut net = Net::new();
        for balance in vec![2, 3, 4, 1] {
            let identity = net.initialize_proc();

            let mut packets = net.on_proc(&identity, |p| p.request_membership()).unwrap();
            while let Some(packet) = packets.pop() {
                packets.extend(net.deliver_packet(packet));
            }

            net.anti_entropy();

            // TODO: add a test where the initiating identity is different from hte owner account
            let mut packets = net.open_account(identity, identity, balance).unwrap();
            while let Some(packet) = packets.pop() {
                packets.extend(net.deliver_packet(packet));
            }
        }

        let a = net.find_identity_with_balance(1).unwrap();
        let b = net.find_identity_with_balance(2).unwrap();
        let c = net.find_identity_with_balance(3).unwrap();

        let mut first_broadcast_packets = net.transfer(a, a, b, 1).unwrap();
        let mut second_broadcast_packets = net.transfer(a, a, c, 1).unwrap();

        let mut packet_number = 0;
        let mut packet_queue: Vec<Packet<Op>> = Vec::new();
        let packet_interleave = vec![0, 0, 15, 9, 67, 99];

        // Interleave the initial broadcast packets
        while first_broadcast_packets.len() > 0 || second_broadcast_packets.len() > 0 {
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

        assert!(net.everyone_is_in_agreement());

        let a_final_balance = net.balance_from_pov_of_proc(&a, &a).unwrap();
        let b_final_balance = net.balance_from_pov_of_proc(&b, &b).unwrap();
        let c_final_balance = net.balance_from_pov_of_proc(&c, &c).unwrap();

        assert_eq!(a_final_balance, 1);
        assert_eq!(b_final_balance, 2);
        assert_eq!(c_final_balance, 3);

        assert_eq!(net.n_packets, 61);
    }
}
