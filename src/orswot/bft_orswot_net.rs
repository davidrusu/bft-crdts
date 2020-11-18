#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashSet};

    use crdts::quickcheck::{quickcheck, TestResult};
    use crdts::{CmRDT, Orswot};

    use crate::actor::Actor;
    use crate::deterministic_secure_broadcast::Packet;
    use crate::net::Net;
    use crate::orswot::bft_orswot::BFTOrswot;
    use crate::traits::SecureBroadcastAlgorithm;

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

    #[test]
    fn test_sequential_adds_run_cuncurrently() {
        let mut net = Net::new();
        bootstrap_net(&mut net, 1);
        let actor = net.members().into_iter().nth(0).unwrap();

        // Initiate the signing round DSB but don't deliver signatures
        let pending_packets = net
            .on_proc(&actor, |proc| {
                proc.exec_algo_op(|orswot| Some(orswot.add(0)))
            })
            .unwrap()
            .into_iter()
            .flat_map(|p| net.deliver_packet(p))
            .collect::<Vec<_>>();

        // Initiate the signing round again but for a different op (adding 1 instead of 0)
        let invalid_pending_packets = net
            .on_proc(&actor, |proc| {
                proc.exec_algo_op(|orswot| Some(orswot.add(1)))
            })
            .unwrap()
            .into_iter()
            .flat_map(|p| net.deliver_packet(p))
            .collect::<Vec<_>>();

        assert_eq!(net.count_invalid_packets(), 0); // At the DSB level, these messages appear fine

        // running through the first batch of pending messages completes as expected
        net.run_packets_to_completion(pending_packets);

        assert!(net.members_are_in_agreement());
        assert_eq!(
            net.on_proc(&actor, |p| p.state().algo_state.read().val),
            Some(vec![0u8].into_iter().collect())
        );
        assert_eq!(
            net.on_proc(&actor, |p| p.read_state(|orswot| orswot.invalid_packets)),
            Some(0)
        );

        // The second batch is detected as faulty and dropped.
        net.run_packets_to_completion(invalid_pending_packets);
        assert!(net.members_are_in_agreement());
        assert_eq!(
            net.on_proc(&actor, |p| p.state().algo_state.read().val),
            Some(vec![0u8].into_iter().collect())
        );
        assert_eq!(
            net.on_proc(&actor, |p| p.read_state(|orswot| orswot.invalid_packets)),
            Some(1) // ensure we have detected an invalid packet
        );
    }

    #[test]
    fn test_concurrent_op_and_member_change() {
        let mut net = Net::new();
        bootstrap_net(&mut net, 3);
        let mut members = net.members().into_iter();
        let (a, b, c) = (
            members.next().unwrap(),
            members.next().unwrap(),
            members.next().unwrap(),
        );

        let value_to_add = 32;

        // initiating process 'a' broadcasts requests for validation
        let req_for_valid_packets = net
            .on_proc(&a, |p| {
                p.exec_algo_op(|orswot| Some(orswot.add(value_to_add)))
            })
            .unwrap();

        // we deliver these packets to destinations
        // and collect responses with signatures
        let signed_validated_packets: Vec<_> = req_for_valid_packets
            .into_iter()
            .flat_map(|p| net.deliver_packet(p))
            .collect();

        // signatures are delivered back to 'a' who then procedes to
        // broadcast the proof of agreement back to the network.
        let proofs_packets = signed_validated_packets
            .into_iter()
            .flat_map(|p| net.deliver_packet(p))
            .collect();

        // hold onto the proofs, don't deliver them till we've removed a few members
        net.run_packets_to_completion(net.on_proc(&b, |p| p.kill_peer(b)).unwrap());
        net.run_packets_to_completion(net.on_proc(&c, |p| p.kill_peer(c)).unwrap());
        net.run_packets_to_completion(proofs_packets);

        assert!(net.members_are_in_agreement());
        assert_eq!(net.count_invalid_packets(), 0);
        assert!(net
            .on_proc(&a, |p| p.state().algo_state.contains(&value_to_add).val)
            .unwrap());
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


        fn prop_interpreter(instructions: Vec<(u8, u8, u8)>) -> TestResult {
            if instructions.len() > 12 {
                return TestResult::discard();
            }

            println!("------");
            println!("instr: {:?}", instructions);
            let mut net: Net<BFTOrswot<u8>> = Net::new();
            let genesis_actor = net.initialize_proc();
            net.on_proc_mut(&genesis_actor, |p| p.trust_peer(genesis_actor)).unwrap();

            let mut packet_queues: BTreeMap<(Actor, Actor), Vec<Packet<_>>> = Default::default();
            let mut model: Orswot<u8, Actor> = Default::default();
            let mut blocked: HashSet<Actor> = Default::default();

            for mut instr in instructions {
                let members: Vec<_> = net.members().into_iter().collect();
                instr.0 = instr.0 % 6;
                match instr {
                    (0, queue_idx, _)  if packet_queues.len() > 0 => {
                        // deliver packet
                        let queue = packet_queues.keys().nth(queue_idx as usize % packet_queues.len()).cloned().unwrap();
                        let packets = packet_queues.entry(queue).or_default();
                        if packets.len() > 0 {
                            let packet = packets.remove(0);

                            if packet.payload.is_proof_of_agreement() {
                                // we are completing the transaction, the source is no longer blocked
                                assert!(blocked.remove(&packet.source));
                            }

                            for resp_packet in net.deliver_packet(packet) {
                                let queue = (resp_packet.source.clone(), resp_packet.dest.clone());
                                packet_queues
                                    .entry(queue)
                                    .or_default()
                                    .push(resp_packet)
                            }
                        }
                    }
                    (1, _, _) if net.actors().len() < 7 => {
                        // add peer
                        let actor = net.initialize_proc();
                        net.on_proc_mut(&actor, |p| p.trust_peer(genesis_actor));
                        let genesis_state = net.proc_from_actor(&genesis_actor).unwrap().state();
                        net.on_proc_mut(&actor, |p| p.sync_from(genesis_state));
                    }
                    (2, actor_idx, _) if !members.is_empty() => {
                        // request membership
                        let actor = members[actor_idx as usize % members.len()].clone();
                        if blocked.contains(&actor) {continue};
                        blocked.insert(actor.clone());

                        for packet in net.on_proc(&actor, |p| p.request_membership()).unwrap() {
                            for resp_packet in net.deliver_packet(packet) {
                                let queue = (resp_packet.source.clone(), resp_packet.dest.clone());
                                packet_queues
                                    .entry(queue)
                                    .or_default()
                                    .push(resp_packet)
                            }
                        }
                    }
                    (3, actor_idx, v) if !members.is_empty() => {
                        // add v
                        let actor = members[actor_idx as usize % members.len()].clone();
                        if blocked.contains(&actor) {continue};
                        blocked.insert(actor.clone());

                        model.apply(model.add(v, model.read_ctx().derive_add_ctx(actor)));
                        for packet in net.on_proc(&actor, |p| p.exec_algo_op(|orswot| Some(orswot.add(v)))).unwrap() {
                            for resp_packet in net.deliver_packet(packet) {
                                let queue = (resp_packet.source.clone(), resp_packet.dest.clone());
                                packet_queues
                                    .entry(queue)
                                    .or_default()
                                    .push(resp_packet)
                            }
                        }
                    }
                    (4, actor_idx, v)  if !members.is_empty() => {
                        // remove v
                        let actor = members[actor_idx as usize % members.len()].clone();
                        if blocked.contains(&actor) {continue};
                        blocked.insert(actor.clone());

                        model.apply(model.rm(v, model.contains(&v).derive_rm_ctx()));

                        for packet in net.on_proc(&actor, |p| p.exec_algo_op(|orswot| orswot.rm(v))).unwrap() {
                            for resp_packet in net.deliver_packet(packet) {
                                let queue = (resp_packet.source.clone(), resp_packet.dest.clone());
                                packet_queues
                                    .entry(queue)
                                    .or_default()
                                    .push(resp_packet)
                            }
                        }
                    }
                    (5, actor_idx, target_actor_idx) if !members.is_empty() => {
                        // kill peer
                        let actor = members[actor_idx as usize % members.len()].clone();
                        if blocked.contains(&actor) {continue};
                        blocked.insert(actor.clone());
                        let target_actor = members[target_actor_idx as usize % members.len()].clone();
                        for packet in net.on_proc(&actor, |p| p.kill_peer(target_actor)).unwrap() {
                            for resp_packet in net.deliver_packet(packet) {
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

            println!("--- draining packet queues ---");
            for (_queue, packets) in packet_queues {
                net.run_packets_to_completion(packets);
            }

            assert!(net.members_are_in_agreement());
            assert_eq!(net.count_invalid_packets(), 0);
            assert_eq!(
                net.on_proc(&genesis_actor, |p| {
                    p.state().algo_state
                }),
                Some(model)
            );

            TestResult::passed()
        }
    }
}
