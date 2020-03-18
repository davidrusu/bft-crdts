use crdts::{CvRDT, CmRDT, orswot};
use std::collections::HashMap;

// we use low cardinality types to improve the chances of interesting
// things happening in our randomized testing
type Actor = u8;
type Data = u8;
type Crdt = orswot::Orswot<Data, Actor>;
type Op = orswot::Op<Data, Actor>;

#[derive(Debug)]
struct Replica {
    id: Actor,
    state: Crdt,
    // logs: HashMap<Actor, Vec<Op>>  TODO: store ops in replicas to test for  op based replication.
}

impl Replica {
    fn new(replica_id: Actor) -> Self {
        Replica {
            id: replica_id,
            state: Crdt::new(),
            // logs: HashMap::new()
        }
    }

    fn recv_op(&mut self, op: Op) {
        self.state.apply(op);
    }

    fn recv_state(&mut self, state: Crdt) {
        self.state.merge(state);
    }
}

#[derive(Debug)]
struct Network {
    mythical_global_state: Crdt,
    replicas: HashMap<Actor, Replica>,
}

#[derive(Debug, Clone)]
enum NetworkEvent {
    Nop,
    AddReplica(Actor),
    SendStateOp(Actor, Op),
    // DisableReplica(Actor),
    // EnableReplica(Actor),
}

impl Network {
    fn new() -> Self {
        Network {
            mythical_global_state: Crdt::new(), 
            replicas: HashMap::new()
        }
    }

    fn step(&mut self, event: NetworkEvent) {
        match event {
            NetworkEvent::Nop => (),
            NetworkEvent::AddReplica(replica_id) => {
                if self.replicas.contains_key(&replica_id) {
                    // TODO: what is the expected behaviour if a replica trys to join with the same
                    //       replica id as an existing one.
                    //       for now we drop the op.
                } else {
                    self.replicas.insert(replica_id, Replica::new(replica_id));
                }
            },
            NetworkEvent::SendStateOp(replica_id, op) => {
                if let Some(replica) = self.replicas.get_mut(&replica_id) {
                    self.mythical_global_state.apply(op.clone());
                    replica.recv_op(op);
                } else {
                    // drop the op
                }
            }
        }
    }

    fn sync_replicas(&mut self) {
        // TAI: should we instead be syncing Op's instead of State's?
        // There's a chance that would generate different byzantine faults under
        // the different replication modes.. maybe add tests for both

        let replica_states: Vec<Crdt> = self.replicas
            .values()
            .map(|e| e.state.clone())
            .collect();

        self.replicas.iter_mut().for_each(|(_, replica)| {
            for other_state in replica_states.iter().cloned() {
                replica.recv_state(other_state);
            }
        });
    }

    fn check_replicas_converge_to_global_state(&self) -> bool {
        let replica_global_state = self.replicas
            .iter()
            .map(|(_, e)| e.state.clone())
            .fold(Crdt::new(), |mut accum, crdt| {
                accum.merge(crdt);
                accum
            });

        replica_global_state == self.mythical_global_state
    }

    fn check_all_replicas_have_same_state(&self) -> bool {
        match self.replicas.values().next() {
            Some(some_replica) =>
                self.replicas.values().all(|e| e.state == some_replica.state),
            None => true
        }
    }
}

fn main() {
    println!("psst. run `QUICKCHECK_TESTS=100000 cargo test` instead");
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::{Arbitrary, Gen, quickcheck};
    use crdts::vclock::{Dot, VClock};
    use hashbrown::HashSet; // TODO: push out a new version of `crdts` to get rid of this hashbrown dep


    impl Arbitrary for NetworkEvent {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let member = Data::arbitrary(g);

            // TODO: move this into an `impl Arbitrary for Dot`
            let dot = Dot {
                actor: Actor::arbitrary(g),
                counter: u64::arbitrary(g) % 100 // TODO: is this fair?
            };

            // TODO: move this into an `impl Arbitrary for VClock`
            let mut clock = VClock::new();
            for _ in 0..(u8::arbitrary(g) % 10) { // TODO: this % 10 is not nice
                clock.apply(Dot {
                    actor: Actor::arbitrary(g),
                    counter: u64::arbitrary(g) % 100  // TODO: is this fair?
                });
            }

            let mut members = HashSet::new();
            for _ in 0..(u8::arbitrary(g) % 10) { // TODO: this % 10 is not nice
                members.insert(Data::arbitrary(g));
            }

            match u8::arbitrary(g) % 4 {
                0 => NetworkEvent::Nop,
                1 => NetworkEvent::AddReplica(Actor::arbitrary(g)),
                // TODO: It would be really nice to generate op's polymorphically over the chosen
                //       CRDT type, right now we only hard code fuzzing for Orswot ops.
                2 => NetworkEvent::SendStateOp(Actor::arbitrary(g), Op::Add { member, dot }),
                3 => NetworkEvent::SendStateOp(Actor::arbitrary(g), Op::Rm { members, clock }),
                _ => panic!("tried to generate invalid network event")
            }
        }
    }
    
    quickcheck! {
        fn replicas_converge_to_global_state(network_events: Vec<NetworkEvent>) -> bool {
            let mut net = Network::new();

            for event in network_events {
                net.step(event);
            }

            net.check_replicas_converge_to_global_state()
        }

        fn replicas_have_same_state_after_syncing(network_events: Vec<NetworkEvent>) -> bool {
            let mut net = Network::new();

            for event in network_events {
                net.step(event);
            }

            net.sync_replicas();
            net.check_all_replicas_have_same_state()
        }
    }
}
