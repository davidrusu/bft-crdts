use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::Hash;

use crdts::Orswot;
use serde::Serialize;

use crate::at2::bft_orswot::BFTOrswot;
use crate::at2::net::Net;
use crate::at2::traits::SecureBroadcastAlgorithm;

impl<M: Clone + Eq + Hash + Debug + Serialize> Net<BFTOrswot<M>> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crdts::quickcheck::{quickcheck, TestResult};

    quickcheck! {
        fn prop_adds_show_up_on_read(n_procs: u8, members: Vec<u8>) -> TestResult {
            if n_procs == 0 || n_procs > 7 || members.len() > 10 {
                return TestResult::discard();
            }

            let mut net: Net<BFTOrswot<u8>> = Net::new();
            for _ in 0..n_procs {
                let id = net.initialize_proc();

                let packets_to_req_membership = net.on_proc(&id, |p| p.request_membership()).unwrap();
                net.run_packets_to_completion(packets_to_req_membership);
                net.anti_entropy();
            }

            assert_eq!(net.members(), net.identities());
            assert!(net.members_are_in_agreement());

            let identities_loop = net.identities().into_iter().collect::<Vec<_>>().into_iter().cycle();
            for (i, member) in identities_loop.zip(members.clone().into_iter()) {
                net.run_packets_to_completion(
                    net.on_proc(&i, |p| p.exec_algo_op(|orswot| Some(orswot.add(member)))).unwrap()
                )
            }

            assert!(net.members_are_in_agreement());

            let orswot: Orswot<_, _> = net.on_proc(
                &net.identities().into_iter().next().unwrap(),
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
            for _ in 0..n_procs {
                let id = net.initialize_proc();
                net.run_packets_to_completion(
                    net.on_proc(&id, |p| p.request_membership()).unwrap(),
                );
                net.anti_entropy();
            }

            assert_eq!(net.members(), net.identities());
            assert!(net.members_are_in_agreement());


            // Model testing against the HashSet
            let mut model = HashSet::new();

            let identities_loop = net.identities().into_iter().collect::<Vec<_>>().into_iter().cycle();
            for (i, (member, adding)) in identities_loop.zip(members.into_iter()) {
                if adding {
                    model.insert(member.clone());
                    net.run_packets_to_completion(
                        net.on_proc(&i, |p| p.exec_algo_op(|orswot| Some(orswot.add(member)))).unwrap()
                    );
                } else {
                    model.remove(&member);
                    net.run_packets_to_completion(
                        net.on_proc(&i, |p| p.exec_algo_op(|orswot| orswot.rm(member))).unwrap()
                    );
                }
            }

            assert!(net.members_are_in_agreement());

            let orswot: Orswot<_, _> = net.on_proc(
                &net.identities().into_iter().next().unwrap(),
                |p| p.read_state(|orswot| orswot.state())
            ).unwrap();

            assert_eq!(model, orswot.read().val);

            TestResult::passed()
        }
    }
}
