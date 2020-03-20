use crdts::{orswot, vclock::Dot, vclock::VClock, CmRDT, CvRDT};
use std::cmp::{Ordering, PartialOrd};
use std::collections::{BTreeSet, HashMap}; // TODO: can we replace HashMap with BTreeMap

// we use low cardinality types to improve the chances of interesting
// things happening in our randomized testing
type Actor = u8;
type Data = u8;
type Crdt = orswot::Orswot<Data, Actor>;
type Op = orswot::Op<Data, Actor>;

/// Causal CRDT's such as ORSWOT and Map need causal ordering on
/// Op delivery. To satisfy this constraint, we introduce the
/// CausalityEnforcer as a fault tolerance layer to be used in each replica.
///
/// The basic mechanism is to buffer an Op if there is a gap in versions.
///
/// Implementation note: We adapt this idea from `Version Vector with Exceptions`
/// also known as `Concise Vectors`, see this paper for details:
/// https://dahliamalkhi.files.wordpress.com/2016/08/winfs-version-vectors-disc2005.pdf
///
/// Assumptions:
/// 1. Replicas have a global version they increment for each Op.
/// 2. Replicas will always increment by 1 for each op they make.
/// 3. Replica versions start at 0, the first Op will have version 1.
#[derive(Debug)]
struct CausalityEnforcer {
    knowledge: VClock<Actor>, // the current version of data accepted into the materialized state
    forward_exceptions: HashMap<Actor, BTreeSet<WrappedOp>>, // Op's this replica has received out of order are stored buffered here
}

impl CausalityEnforcer {
    fn new() -> Self {
        CausalityEnforcer {
            knowledge: VClock::new(),
            forward_exceptions: HashMap::new(),
        }
    }

    fn enforce(&mut self, op: WrappedOp) -> Vec<WrappedOp> {
        if self.knowledge > VClock::from(op.source_version.clone()) {
            // we've already seen this op, drop it

            assert!(!self
                .forward_exceptions
                .entry(op.source_version.actor)
                .or_default()
                .contains(&op));

            vec![]
        } else if self.knowledge.get(&op.source_version.actor) + 1 == op.source_version.counter {
            // This is new information that directly follows from the current version

            assert!(!self
                .forward_exceptions
                .entry(op.source_version.actor)
                .or_default()
                .contains(&op));

            self.knowledge.apply(op.source_version.clone());
            let replica_exceptions = self
                .forward_exceptions
                .entry(op.source_version.actor)
                .or_default();

            let ops_that_are_now_safe_to_apply = replica_exceptions.iter().cloned().scan(
                op.source_version.counter,
                |previous_counter, exception_op| {
                    if *previous_counter + 1 == exception_op.source_version.counter {
                        Some(exception_op)
                    } else {
                        None
                    }
                },
            );

            let mut in_order_ops = BTreeSet::new();
            in_order_ops.insert(op);
            in_order_ops.extend(ops_that_are_now_safe_to_apply);

            for consumed_op in in_order_ops.iter() {
                replica_exceptions.remove(consumed_op);
            }

            in_order_ops.into_iter().collect()
        } else {
            // This is an Op we've received out of order, we need to create an exception for it
            // so that once we fill in the missing op's, we can then apply this op
            self.forward_exceptions
                .entry(op.source_version.actor)
                .or_default()
                .insert(op);

            vec![]
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WrappedOp {
    op: Op,
    source_version: Dot<Actor>,
}

impl PartialOrd for WrappedOp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.source_version.actor != other.source_version.actor {
            return None;
        }

        self.source_version
            .counter
            .partial_cmp(&other.source_version.counter)
    }
}

impl Ord for WrappedOp {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(&other).unwrap()
    }
}

#[derive(Debug)]
struct Replica {
    id: Actor,
    state: Crdt,
    logs: HashMap<Actor, Vec<WrappedOp>>, // the history of edits made by each actor
    causality_enforcer: CausalityEnforcer,
}

impl Replica {
    fn new(replica_id: Actor) -> Self {
        Replica {
            id: replica_id,
            state: Crdt::new(),
            logs: HashMap::new(),
            causality_enforcer: CausalityEnforcer::new(),
        }
    }

    fn recv_op(&mut self, wrapped_op: WrappedOp) {
        for causally_ordered_wrapped_op in self.causality_enforcer.enforce(wrapped_op) {
            // Store the op for replication
            self.logs
                .entry(causally_ordered_wrapped_op.source_version.actor)
                .or_default()
                .push(causally_ordered_wrapped_op.clone());

            // apply the op to our local state
            self.state.apply(causally_ordered_wrapped_op.op);
        }
    }

    fn recv_state(&mut self, state: Crdt) {
        self.state.merge(state);
    }
}

#[derive(Debug)]
struct Network {
    mythical_global_state: Crdt,
    causality_enforcer: CausalityEnforcer,
    replicas: HashMap<Actor, Replica>,
}

#[derive(Debug, Clone)]
enum NetworkEvent {
    Nop,
    AddReplica(Actor),
    SendOp(Actor, WrappedOp),
    // DisableReplica(Actor),
    // EnableReplica(Actor),
}

impl Network {
    fn new() -> Self {
        Network {
            mythical_global_state: Crdt::new(),
            causality_enforcer: CausalityEnforcer::new(),
            replicas: HashMap::new(),
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
            }
            NetworkEvent::SendOp(dest, wrapped_op) => {
                if let Some(replica) = self.replicas.get_mut(&dest) {
                    for ordered_op in self.causality_enforcer.enforce(wrapped_op.clone()) {
                        self.mythical_global_state.apply(ordered_op.op);
                    }

                    replica.recv_op(wrapped_op);
                } else {
                    // drop the op
                }
            }
        }
    }

    fn sync_replicas_via_op_replication(&mut self) {
        let replica_op_logs: Vec<Vec<WrappedOp>> = self
            .replicas
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
        let replica_states: Vec<Crdt> = self.replicas.values().map(|r| r.state.clone()).collect();

        self.replicas.iter_mut().for_each(|(_, replica)| {
            for other_state in replica_states.iter().cloned() {
                replica.recv_state(other_state);
            }
        });
    }

    fn check_replicas_converge_to_global_state(&self) -> bool {
        let replica_global_state = self.replicas.iter().map(|(_, e)| e.state.clone()).fold(
            Crdt::new(),
            |mut accum, crdt| {
                accum.merge(crdt);
                accum
            },
        );

        replica_global_state == self.mythical_global_state
    }

    fn check_all_replicas_have_same_state(&self) -> bool {
        match self.replicas.values().next() {
            Some(some_replica) => self
                .replicas
                .values()
                .all(|e| e.state == some_replica.state),
            None => true,
        }
    }
}

fn main() {
    println!("psst. run `QUICKCHECK_TESTS=100000 cargo test` instead");
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashbrown::HashSet;
    use quickcheck::{quickcheck, Arbitrary, Gen}; // TODO: push out a new version of `crdts` to get rid of this hashbrown dep

    impl Arbitrary for NetworkEvent {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let member = Data::arbitrary(g);

            // TODO: move this into an `impl Arbitrary for Dot`
            let dot = Dot {
                actor: Actor::arbitrary(g),
                counter: u64::arbitrary(g) % 100, // TODO: is this fair?
            };

            // TODO: move this into an `impl Arbitrary for VClock`
            let mut clock = VClock::new();
            for _ in 0..(u8::arbitrary(g) % 10) {
                // TODO: this % 10 is not nice
                clock.apply(Dot {
                    actor: Actor::arbitrary(g),
                    counter: u64::arbitrary(g) % 100, // TODO: is this fair?
                });
            }

            let mut members = HashSet::new();
            for _ in 0..(u8::arbitrary(g) % 10) {
                // TODO: this % 10 is not nice
                members.insert(Data::arbitrary(g));
            }

            // TODO: It would be really nice to generate op's polymorphically over the chosen
            //       CRDT type, right now we only hard code fuzzing for Orswot ops.
            let op = match u8::arbitrary(g) % 2 {
                0 => Op::Add { member, dot },
                1 => Op::Rm { members, clock },
                _ => panic!("tried to generate invalid op"),
            };

            let source = Actor::arbitrary(g);
            let dest = Actor::arbitrary(g);
            let source_version = Dot {
                actor: source,
                counter: u64::arbitrary(g), // TODO: modulo something small to improve chances of things happening
            };
            let wrapped_op = WrappedOp { op, source_version };

            match u8::arbitrary(g) % 3 {
                0 => NetworkEvent::Nop,
                1 => NetworkEvent::AddReplica(Actor::arbitrary(g)),
                2 => NetworkEvent::SendOp(dest, wrapped_op),
                _ => panic!("tried to generate invalid network event"),
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
            NetworkEvent::SendOp(
                2,
                WrappedOp {
                    op: Op::Add {
                        dot: Dot {
                            actor: 32,
                            counter: 2,
                        },
                        member: 88,
                    },
                    source_version: Dot {
                        actor: 32,
                        counter: 2,
                    },
                },
            ),
            NetworkEvent::AddReplica(3),
            NetworkEvent::SendOp(
                3,
                WrappedOp {
                    op: Op::Add {
                        dot: Dot {
                            actor: 32,
                            counter: 1,
                        },
                        member: 57,
                    },
                    source_version: Dot {
                        actor: 32,
                        counter: 1,
                    },
                },
            ),
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
            NetworkEvent::SendOp(
                7,
                WrappedOp {
                    op: Op::Add {
                        dot: Dot {
                            actor: 64,
                            counter: 33,
                        },
                        member: 20,
                    },
                    source_version: Dot {
                        actor: 10,
                        counter: 33,
                    },
                },
            ),
            NetworkEvent::AddReplica(59),
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
            NetworkEvent::SendOp(
                7,
                WrappedOp {
                    op: Op::Add {
                        dot: Dot {
                            actor: 64,
                            counter: 33,
                        },
                        member: 20,
                    },
                    source_version: Dot {
                        actor: 10,
                        counter: 33, // TODO: what if this counter does not match the dot's counter
                    },
                },
            ),
            NetworkEvent::AddReplica(59),
        ];

        for event in network_events {
            net.step(event);
        }

        net.sync_replicas_via_state_replication();
        assert!(net.check_all_replicas_have_same_state());
    }

    #[test]
    fn test_causal_order_enforcer_reordering() {
        let mut enforcer = CausalityEnforcer::new();
        let op2 = WrappedOp {
            op: Op::Add {
                dot: Dot {
                    actor: 43,
                    counter: 87,
                },
                member: 69,
            },
            source_version: Dot {
                actor: 4,
                counter: 2,
            },
        };
        let op1 = WrappedOp {
            op: Op::Add {
                dot: Dot {
                    actor: 1,
                    counter: 44,
                },
                member: 29,
            },
            source_version: Dot {
                actor: 4,
                counter: 1,
            },
        };

        assert_eq!(enforcer.enforce(op2.clone()), vec![]);
        assert_eq!(enforcer.enforce(op1.clone()), vec![op1, op2])
    }
}

// TODO: add test for to verify that op based and state based replication both converge to the same state.
