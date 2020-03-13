use crdts::{CvRDT, CmRDT, orswot};
use std::collections::HashMap;

// we use low cardinality types to improve the chances of interesting
// things happening in our randomized testing
type Actor = u8;
type Data = u8;
type Crdt = orswot::Orswot<Data, Actor>;
type Op = orswot::Op<Data, Actor>;

#[derive(Debug)]
struct Elder {
    id: Actor,
    state: Crdt,
    // logs: HashMap<Actor, Vec<Op>>  TODO: store ops in elders to test for  op based replication.
}

impl Elder {
    fn new(elder_id: Actor) -> Self {
        Elder {
            id: elder_id,
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
    elders: HashMap<Actor, Elder>,
}

#[derive(Debug, Clone)]
enum NetworkEvent {
    Nop,
    AddElder(Actor),
    SendStateOp(Actor, Op),
    // DisableElder(Actor),
    // EnableElder(Actor),
}

impl Network {
    fn new() -> Self {
        Network {
            mythical_global_state: Crdt::new(), 
            elders: HashMap::new()
        }
    }

    fn step(&mut self, event: NetworkEvent) {
        match event {
            NetworkEvent::Nop => (),
            NetworkEvent::AddElder(elder_id) => {
                if self.elders.contains_key(&elder_id) {
                    // TODO: what is the expected behaviour if an elder trys to join with the same
                    //       elder id as an existing one.
                    //       for now we drop the op.
                } else {
                    self.elders.insert(elder_id, Elder::new(elder_id));
                }
            },
            NetworkEvent::SendStateOp(elder_id, op) => {
                if let Some(elder) = self.elders.get_mut(&elder_id) {
                    self.mythical_global_state.apply(op.clone());
                    elder.recv_op(op);
                } else {
                    // drop the op
                }
            }
        }
    }

    fn sync_elders(&mut self) {
        // TAI: should we instead be syncing Op's instead of State's?
        // There's a chance that would generate different byzantine faults under
        // the different replication modes.. maybe add tests for both

        let elder_states: Vec<Crdt> = self.elders
            .values()
            .map(|e| e.state.clone())
            .collect();

        self.elders.iter_mut().for_each(|(_, elder)| {
            for other_state in elder_states.iter().cloned() {
                elder.recv_state(other_state);
            }
        });
    }

    fn check_elders_converge_to_global_state(&self) -> bool {
        let elder_global_state = self.elders
            .iter()
            .map(|(_, e)| e.state.clone())
            .fold(Crdt::new(), |mut accum, crdt| {
                accum.merge(crdt);
                accum
            });

        elder_global_state == self.mythical_global_state
    }

    fn check_all_elders_have_same_state(&self) -> bool {
        match self.elders.values().next() {
            Some(some_elder) =>
                self.elders.values().all(|e| e.state == some_elder.state),
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
                1 => NetworkEvent::AddElder(Actor::arbitrary(g)),
                // TODO: It would be really nice to generate op's polymorphically over the chosen
                //       CRDT type, right now we only hard code fuzzing for Orswot ops.
                2 => NetworkEvent::SendStateOp(Actor::arbitrary(g), Op::Add { member, dot }),
                3 => NetworkEvent::SendStateOp(Actor::arbitrary(g), Op::Rm { members, clock }),
                _ => panic!("tried to generate invalid network event")
            }
        }
    }
    
    quickcheck! {
        fn elders_converge_to_global_state(network_events: Vec<NetworkEvent>) -> bool {
            let mut net = Network::new();

            for event in network_events {
                net.step(event);
            }

            net.check_elders_converge_to_global_state()
        }

        fn elders_have_same_state_after_syncing(network_events: Vec<NetworkEvent>) -> bool {
            let mut net = Network::new();

            for event in network_events {
                net.step(event);
            }

            net.sync_elders();
            net.check_all_elders_have_same_state()
        }
    }
}
