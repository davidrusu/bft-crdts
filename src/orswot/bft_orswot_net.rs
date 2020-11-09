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
            net.run_packets_to_completion(net.on_proc(&actor, |p| p.request_membership()).unwrap());
            net.anti_entropy();
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
    }
}
