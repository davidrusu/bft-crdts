use std::fmt::Debug;
use std::hash::Hash;

use serde::Serialize;

use crate::net::Net;
use crate::orswot::bft_orswot::BFTOrswot;

impl<M: Clone + Eq + Hash + Debug + Serialize> Net<BFTOrswot<M>> {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    use crate::traits::SecureBroadcastAlgorithm;
    use crdts::quickcheck::{quickcheck, TestResult};
    use crdts::Orswot;

    fn bootstrap_net(net: &mut Net<BFTOrswot<u8>>, n_procs: u8) {
        let genesis_actor = net.initialize_proc();
        net.on_proc_mut(&genesis_actor, |p| p.trust_peer(genesis_actor))
            .unwrap();

        // 1 proc was taken by the genesis, so subtract 1
        for _ in 0..(n_procs - 1) {
            let actor = net.initialize_proc();
            net.on_proc_mut(&actor, |p| p.trust_peer(genesis_actor));
            net.anti_entropy();
            net.run_packets_to_completion(net.on_proc(&actor, |p| p.request_membership()).unwrap());
        }

        assert_eq!(net.members(), net.actors());
        assert!(net.members_are_in_agreement());
    }

    quickcheck! {
        fn prop_adds_show_up_on_read(n_procs: u8, members: Vec<u8>) -> TestResult {
            if n_procs == 0 || n_procs > 7 || members.len() > 10 {
                return TestResult::discard();
            }

            let mut net: Net<BFTOrswot<u8>> = Net::new();
            bootstrap_net(&mut net, n_procs);

            let actors_loop = net.actors().into_iter().collect::<Vec<_>>().into_iter().cycle();
            for (i, member) in actors_loop.zip(members.clone().into_iter()) {
                net.run_packets_to_completion(
                    net.on_proc(&i, |p| p.exec_algo_op(|orswot| Some(orswot.add(member)))).unwrap()
                )
            }

            assert!(net.members_are_in_agreement());

            let orswot: Orswot<_, _> = net.on_proc(
                &net.actors().into_iter().next().unwrap(),
                |p| p.read_state(|orswot| orswot.state())
            ).unwrap();

            assert_eq!(members.into_iter().collect::<HashSet<_>>(), orswot.read().val);

            TestResult::passed()
        }

        fn prop_adds_and_removes_behave_as_hashset(n_procs: u8, members: Vec<(u8, bool)>) -> TestResult {
            if n_procs == 0 || n_procs > 7 || members.len() > 10 {
                return TestResult::discard();
            }

            let mut net: Net<BFTOrswot<u8>> = Net::new();
            bootstrap_net(&mut net, n_procs);

            // Model testing against the HashSet
            let mut model = HashSet::new();

            let actors_loop = net.actors().into_iter().collect::<Vec<_>>().into_iter().cycle();
            for (actor, (member, adding)) in actors_loop.zip(members.into_iter()) {
                if adding {
                    model.insert(member.clone());
                    net.run_packets_to_completion(
                        net.on_proc(&actor, |p| p.exec_algo_op(|orswot| Some(orswot.add(member)))).unwrap()
                    );
                } else {
                    model.remove(&member);
                    net.run_packets_to_completion(
                        net.on_proc(&actor, |p| p.exec_algo_op(|orswot| orswot.rm(member))).unwrap()
                    );
                }
            }

            assert!(net.members_are_in_agreement());

            let orswot: Orswot<_, _> = net.on_proc(
                &net.actors().into_iter().next().unwrap(),
                |p| p.read_state(|orswot| orswot.state())
            ).unwrap();

            assert_eq!(model, orswot.read().val);

            TestResult::passed()
        }

        fn prop_interpreter(instructions: Vec<(u8, u8, u8)>) -> bool{
            let mut net: Net<BFTOrswot<u8>> = Net::new();
            let genesis_actor = net.initialize_proc();
            net.on_proc_mut(&genesis_actor, |p| p.trust_peer(genesis_actor)).unwrap();

            let mut pending_packets = Vec::new();
            for instr in instructions {
                let members: Vec<_> = net.members().into_iter().collect();
                match instr {
                    (0, _, _) => {
                        // add peer
                        let actor = net.initialize_proc();
                        net.on_proc_mut(&actor, |p| p.trust_peer(genesis_actor));
                        let genesis_state = net.proc_from_actor(&genesis_actor).unwrap().state();
                        net.on_proc_mut(&actor, |p| p.sync_from(genesis_state));
                    }
                    (1, actor_idx, _) if !members.is_empty() => {
                        // request membership
                        let actor = members[actor_idx as usize % members.len()].clone();
                        pending_packets.extend(net.on_proc(&actor, |p| p.request_membership()).unwrap())
                    }
                    (2, actor_idx, v) if !members.is_empty() => {
                        // add v
                        let actor = members[actor_idx as usize % members.len()].clone();
                        pending_packets.extend(
                            net.on_proc(&actor, |p| p.exec_algo_op(|orswot| Some(orswot.add(v)))).unwrap());
                    }
                    (3, actor_idx, v)  if !members.is_empty() => {
                        // remove v
                        let actor = members[actor_idx as usize % members.len()].clone();
                        pending_packets.extend(
                            net.on_proc(&actor, |p| p.exec_algo_op(|orswot| orswot.rm(v))).unwrap());
                    }
                    (4, packet_idx, _) if !pending_packets.is_empty() => {
                        // deliver packet
                        let packet = pending_packets.remove(packet_idx as usize % pending_packets.len());

                        pending_packets.extend(net.deliver_packet(packet));
                    }
                    (5, actor_idx, target_actor_idx) if !members.is_empty() => {
                        // kill peer
                        let actor = members[actor_idx as usize % members.len()].clone();
                        let target_actor = members[target_actor_idx as usize % members.len()].clone();
                        for packet in net.on_proc(&actor, |p| p.kill_peer(target_actor)).unwrap() {
                            for resp_packet in net.deliver_packet_shortcircuit(packet) {
                                let queue = (resp_packet.source.clone(), resp_packet.dest.clone());
                                packet_queues
                                    .entry(queue)
                                    .or_default()
                                    .push(resp_packet)
                            }
                        }
                    }
                    _ => (),
                }
            }

            net.run_packets_to_completion(pending_packets);
            assert!(net.members_are_in_agreement());
            true
        }
    }
}
