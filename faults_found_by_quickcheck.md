**ISSUE:** error when onboarding replicas
``` rust
[
    NetworkEvent::AddReplica(7),
    NetworkEvent::SendOp(7, WrappedOp { op: Op::Add { dot: Dot { actor: 64, counter: 33 }, member: 20 }, source: 10}),
    NetworkEvent::AddReplica(59)
]
```
We had moved the destination replica into the OpWrapper, and put an assert in the replicas to check the the op was indeed destined for them.

This caused errors when a new replica was added as we needed to replicate the WrappedOp's to the new replica but this replica was rejecting ops that were not destined for it.

Solution: move the destination replica the the NetworkEvent and remove the assert from the replica.

**ISSUE:** event ordering, 2 issues raised by this example:
``` rust
[
    AddReplica(6),
    SendOp(6, WrappedOp { op: Add { dot: Dot { actor: 47, counter: 99 }, member: 88 }, source: 40 }),
    AddReplica(33),
    SendOp(33, WrappedOp { op: Add { dot: Dot { actor: 47, counter: 15 }, member: 57 }, source: 70 })
]
```
1. Causal CRDT's need in-order op replay
2. replicas are accepting ops from sources different from what is inside the Op's Dot.

We don't have a test case for 2. yet, TODO: add a property that would catch this.
