use crdts::{CvRDT, CmRDT, orswot};
use std::collections::HashMap;

// we use low cardinality types to improve the chances of interesting
// things happening in our randomized testing
type Actor = u8;
type Data = u8;
type Crdt = orswot::Orswot<Data, Actor>;
type Op = orswot::Op<Data, Actor>;

#[derive(Debug, Clone)]
struct WrappedOp {
    op: Op,
    source: Actor,
}

#[derive(Debug)]
struct Replica {
    id: Actor,
    state: Crdt,
    logs: HashMap<Actor, Vec<WrappedOp>> // the history of edits made by each actor
}

impl Replica {
    fn new(replica_id: Actor) -> Self {
        Replica {
            id: replica_id,
            state: Crdt::new(),
            logs: HashMap::new()
        }
    }

    fn recv_op(&mut self, wrapped_op: WrappedOp) {
        let op_history = self.logs
            .entry(wrapped_op.source)
            .or_default();

        op_history.push(wrapped_op.clone());
        self.state.apply(wrapped_op.op);
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
    SendOp(Actor,WrappedOp),
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
            NetworkEvent::SendOp(dest, wrapped_op) => {
                if let Some(replica) = self.replicas.get_mut(&dest) {
                    self.mythical_global_state.apply(wrapped_op.op.clone());
                    replica.recv_op(wrapped_op);
                } else {
                    // drop the op
                }
            }
        }
    }

    fn sync_replicas_via_op_replication(&mut self) {
        let replica_op_logs: Vec<Vec<WrappedOp>> = self.replicas
            .values()
            .flat_map(|r| r.logs.values().cloned().collect::<Vec<Vec<WrappedOp>>>())
            .collect();

        self.replicas.iter_mut().for_each(|(_, replica)| {
            for op_log in replica_op_logs.iter().cloned() {
                for wrapped_op in op_log {
                    replica.recv_op(wrapped_op)
                }
            }
        });
    }

    fn sync_replicas_via_state_replication(&mut self) {
        let replica_states: Vec<Crdt> = self.replicas
            .values()
            .map(|r| r.state.clone())
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

            let source = Actor::arbitrary(g);
            let dest = Actor::arbitrary(g);

            // TODO: It would be really nice to generate op's polymorphically over the chosen
            //       CRDT type, right now we only hard code fuzzing for Orswot ops.
            let op = match u8::arbitrary(g) % 2 {
                0 => Op::Add { member, dot },
                1 => Op::Rm { members, clock },
                _ => panic!("tried to generate invalid op")
            };

            let wrapped_op = WrappedOp { op, source };

            match u8::arbitrary(g) % 3 {
                0 => NetworkEvent::Nop,
                1 => NetworkEvent::AddReplica(Actor::arbitrary(g)),
                2 => NetworkEvent::SendOp(dest, wrapped_op),
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

        fn replicas_converge_after_state_based_syncing(network_events: Vec<NetworkEvent>) -> bool {
            let mut net = Network::new();

            for event in network_events {
                net.step(event);
            }

            net.sync_replicas_via_state_replication();
            net.check_all_replicas_have_same_state()
        }

        fn replicas_converge_after_op_based_syncing(network_events: Vec<NetworkEvent>) -> bool {
            let mut net = Network::new();

            for event in network_events {
                net.step(event);
            }

            net.sync_replicas_via_op_replication();
            net.check_all_replicas_have_same_state()
        }

        fn replicas_are_resistant_to_network_event_reordering(network_events: Vec<NetworkEvent>, reorderings: Vec<(u32, u32)>) -> bool {
            // the newtork is commutative over network event
            let mut net_in_order = Network::new();
            let mut net_reordered = Network::new();

            let num_events = network_events.len() as u32;

            // TODO: replace this branch with quickcheck::TestResult::discard()
            if num_events == 0 {
                return true;
            }

            let mut reordered_network_events = network_events.clone();
            for (a, b) in reorderings {
                reordered_network_events.swap((a % num_events)  as usize, (b % num_events) as usize);
            }

            for event in network_events {
                net_in_order.step(event);
            }

            for event in reordered_network_events {
                net_reordered.step(event);
            }

            net_in_order.sync_replicas_via_op_replication();
            if !net_in_order.check_all_replicas_have_same_state() {
                return false
            }

            net_reordered.sync_replicas_via_op_replication();
            if !net_reordered.check_all_replicas_have_same_state() {
                return false
            }

            let any_in_order_state: Option<Crdt> = net_in_order.replicas.values().next().map(|r| r.state.clone());
            let any_reordered_state: Option<Crdt> = net_reordered.replicas.values().next().map(|r| r.state.clone());

            any_in_order_state == any_reordered_state
        }
    }

    #[test]
    fn test_resistance_to_reordering_replica_ops() {
        let mut net = Network::new();

        let network_events = vec![
            NetworkEvent::AddReplica(2),
            NetworkEvent::SendOp(2, WrappedOp { op: Op::Add { dot: Dot { actor: 32, counter: 2 }, member: 88 }, source: 32 }),
            NetworkEvent::AddReplica(3),
            NetworkEvent::SendOp(3, WrappedOp { op: Op::Add { dot: Dot { actor: 32, counter: 1 }, member: 57 }, source: 32 })
        ];

        for event in network_events {
            net.step(event);
        }

        net.sync_replicas_via_op_replication();
        assert!(net.check_all_replicas_have_same_state());
    }

    #[test]
    fn test_new_replicas_are_onboarded_correctly_on_op_sync() {
        let mut net = Network::new();

        let network_events = vec![
            NetworkEvent::AddReplica(7),
            NetworkEvent::SendOp(7, WrappedOp { op: Op::Add { dot: Dot { actor: 64, counter: 33 }, member: 20 }, source: 10}),
            NetworkEvent::AddReplica(59)
        ];

        for event in network_events {
            net.step(event);
        }

        net.sync_replicas_via_op_replication();
        assert!(net.check_all_replicas_have_same_state());
    }

    #[test]
    fn test_new_replicas_are_onboarded_correctly_on_state_sync() {
        let mut net = Network::new();

        let network_events = vec![
            NetworkEvent::AddReplica(7),
            NetworkEvent::SendOp(7, WrappedOp { op: Op::Add { dot: Dot { actor: 64, counter: 33 }, member: 20 }, source: 10}),
            NetworkEvent::AddReplica(59)
        ];

        for event in network_events {
            net.step(event);
        }

        net.sync_replicas_via_state_replication();
        assert!(net.check_all_replicas_have_same_state());
    }
}

// TODO: add test for to verify that op based and state based replication both converge to the same state.
