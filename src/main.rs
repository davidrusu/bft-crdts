use crdts::quickcheck::{Arbitrary, Gen};
use crdts::{orswot, CmRDT, CvRDT, Dot, VClock};
use std::cmp::{Ordering, PartialOrd};
use std::collections::{BTreeSet, HashMap};

mod at2;

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
#[derive(Debug, Default)]
struct CausalityEnforcer {
    /// The most recent version of each actor that has been released to the replica
    knowledge: VClock<Actor>,

    /// If we receive an Msg from a replica that skips a version, we can not apply
    /// this Msg to local state so, we buffer it here.
    ///
    /// The Msg is ordered on the version counter of the replica that sent it.
    /// We rely on the fact that BTreeSet is ordered to re-order Msg's as we insert them.
    forward_exceptions: HashMap<Actor, BTreeSet<Msg>>,
}

impl CausalityEnforcer {
    fn enforce(&mut self, op: Msg) -> BTreeSet<Msg> {
        if self.knowledge > VClock::from(op.source_version) {
            // we've already seen this op, drop it
            assert!(self.verify_no_exception_for(&op));
            BTreeSet::new()
        } else if self.knowledge.get(&op.source_version.actor) + 1 == op.source_version.counter {
            // This is new information that directly follows from the current version
            assert!(self.verify_no_exception_for(&op));

            self.knowledge.apply(op.source_version.clone());
            let replica_exceptions = self
                .forward_exceptions
                .entry(op.source_version.actor)
                .or_default();

            let ops_that_are_now_safe_to_apply = replica_exceptions.iter().cloned().scan(
                op.source_version,
                |previous_version, exception_op| {
                    if previous_version.inc() == exception_op.source_version {
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

            in_order_ops
        } else {
            // This is an Op we've received out of order, we need to create an exception for it
            // so that once we've filled in the missing versions from the source replica, we can
            // then apply this op.
            self.forward_exceptions
                .entry(op.source_version.actor)
                .or_default()
                .insert(op);

            BTreeSet::new()
        }
    }

    fn verify_no_exception_for(&self, op: &Msg) -> bool {
        let we_have_an_exception = self
            .forward_exceptions
            .get(&op.source_version.actor)
            .map(|exceptions| exceptions.contains(op))
            .unwrap_or(false);

        !we_have_an_exception
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Msg {
    op: Op,
    source_version: Dot<Actor>,
}

impl PartialOrd for Msg {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.source_version.partial_cmp(&other.source_version)
    }
}

impl Ord for Msg {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(&other).unwrap()
    }
}

#[derive(Debug)]
struct Replica {
    id: Actor,
    state: Crdt,
    logs: HashMap<Actor, Vec<Msg>>, // the history of edits made by each actor
    causality_enforcer: CausalityEnforcer,
}

impl Replica {
    fn new(replica_id: Actor) -> Self {
        Replica {
            id: replica_id,
            state: Crdt::new(),
            logs: HashMap::new(),
            causality_enforcer: CausalityEnforcer::default(),
        }
    }

    fn recv_op(&mut self, wrapped_op: Msg) {
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
    ReplicaAdded(Actor),
    OpSent(Actor, Msg),
    // FalseOpSent(Actor, Msg), // FalseOps are Op's that did not originate from the source referenced in Msg
    // ReplicaDisabled(Actor),
    // ReplicaEnabled(Actor),
}

impl Network {
    fn new() -> Self {
        Network {
            mythical_global_state: Crdt::new(),
            causality_enforcer: CausalityEnforcer::default(),
            replicas: HashMap::new(),
        }
    }

    fn step(&mut self, event: NetworkEvent) {
        match event {
            NetworkEvent::Nop => (),
            NetworkEvent::ReplicaAdded(replica_id) => {
                // TODO: what is the expected behaviour if a replica trys to join with the same
                //       replica id as an existing one.
                //       for now we drop the op.
                self.replicas
                    .entry(replica_id)
                    .or_insert_with(|| Replica::new(replica_id));
            }
            NetworkEvent::OpSent(dest, wrapped_op) => {
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
        let replica_op_logs: Vec<Vec<Msg>> = self
            .replicas
            .values()
            .flat_map(|r| r.logs.values().cloned().collect::<Vec<Vec<Msg>>>())
            .collect();

        self.replicas.iter_mut().for_each(|(_, replica)| {
            for op_log in replica_op_logs.iter().cloned() {
                for wrapped_op in op_log {
                    replica.recv_op(wrapped_op)
                }
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

impl Arbitrary for NetworkEvent {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        match u8::arbitrary(g) % 3 {
            0 => NetworkEvent::Nop,
            1 => NetworkEvent::ReplicaAdded(Actor::arbitrary(g)),
            2 => NetworkEvent::OpSent(
                Actor::arbitrary(g), // actor to send this op to
                Msg {
                    op: Op::arbitrary(g),
                    source_version: Dot::arbitrary(g),
                },
            ),
            _ => panic!("tried to generate invalid network event"),
        }
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        let mut shrunk_events = Vec::new();
        match self.clone() {
            NetworkEvent::Nop => (),
            NetworkEvent::ReplicaAdded(_) => (),
            NetworkEvent::OpSent(actor, Msg { op, source_version }) => {
                for shrunk_op in op.shrink() {
                    shrunk_events.push(NetworkEvent::OpSent(
                        actor,
                        Msg {
                            op: shrunk_op,
                            source_version,
                        },
                    ));
                }
                for shrunk_version in source_version.shrink() {
                    shrunk_events.push(NetworkEvent::OpSent(
                        actor,
                        Msg {
                            op: op.clone(),
                            source_version: shrunk_version,
                        },
                    ));
                }
            }
        }
        Box::new(shrunk_events.into_iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crdts::quickcheck::quickcheck;

    quickcheck! {
        fn replicas_converge_to_global_state(network_events: Vec<NetworkEvent>) -> bool {
            let mut net = Network::new();

            for event in network_events {
                net.step(event);
            }

            net.check_replicas_converge_to_global_state()
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
            NetworkEvent::ReplicaAdded(2),
            NetworkEvent::OpSent(
                2,
                Msg {
                    op: Op::Add {
                        dot: Dot {
                            actor: 32,
                            counter: 2,
                        },
                        members: vec![88].into_iter().collect(),
                    },
                    source_version: Dot {
                        actor: 32,
                        counter: 2,
                    },
                },
            ),
            NetworkEvent::ReplicaAdded(3),
            NetworkEvent::OpSent(
                3,
                Msg {
                    op: Op::Add {
                        dot: Dot {
                            actor: 32,
                            counter: 1,
                        },
                        members: vec![57].into_iter().collect(),
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
            NetworkEvent::ReplicaAdded(7),
            NetworkEvent::OpSent(
                7,
                Msg {
                    op: Op::Add {
                        dot: Dot {
                            actor: 64,
                            counter: 33,
                        },
                        members: vec![20].into_iter().collect(),
                    },
                    source_version: Dot {
                        actor: 10,
                        counter: 33,
                    },
                },
            ),
            NetworkEvent::ReplicaAdded(59),
        ];

        for event in network_events {
            net.step(event);
        }

        net.sync_replicas_via_op_replication();
        assert!(net.check_all_replicas_have_same_state());
    }

    #[test]
    fn test_causal_order_enforcer_reordering() {
        let mut enforcer = CausalityEnforcer::default();
        let op2 = Msg {
            op: Op::Add {
                dot: Dot {
                    actor: 43,
                    counter: 87,
                },
                members: vec![69].into_iter().collect(),
            },
            source_version: Dot {
                actor: 4,
                counter: 2,
            },
        };
        let op1 = Msg {
            op: Op::Add {
                dot: Dot {
                    actor: 1,
                    counter: 44,
                },
                members: vec![29].into_iter().collect(),
            },
            source_version: Dot {
                actor: 4,
                counter: 1,
            },
        };

        assert_eq!(enforcer.enforce(op2.clone()), BTreeSet::new());
        assert_eq!(
            enforcer.enforce(op1.clone()),
            vec![op1, op2].into_iter().collect()
        )
    }
}
