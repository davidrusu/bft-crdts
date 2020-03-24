##### **ISSUE:** Same replica sends out different op's with the same version
``` rust
[
    AddReplica(49),
    AddReplica(85),
    SendOp(49, WrappedOp { op: Rm { clock: VClock { dots: {4: 3} }, members: {6} }, source_version: Dot { actor: 41, counter: 1 } }),
    SendOp(85, WrappedOp { op: Rm { clock: VClock { dots: {8: 5} }, members: {2} }, source_version: Dot { actor: 41, counter: 1 } })
]
```

**BUG** The 3rd and 4th event are versioned with the same dot, this breaks our `CausalityEnforcer`.
We likely need to add signatures to solve this.

TODO: write a test for this

##### **ISSUE:** error when onboarding replicas
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

##### **ISSUE:** event ordering, 2 issues raised by this example:
``` rust
[
    AddReplica(6),
    SendOp(6, WrappedOp { op: Add { dot: Dot { actor: 47, counter: 99 }, member: 88 }, source: 40 }),
    AddReplica(33),
    SendOp(33, WrappedOp { op: Add { dot: Dot { actor: 47, counter: 15 }, member: 57 }, source: 70 })
]
```
1. ~~Causal CRDT's need in-order op replay~~ solved with `CausalityEnforcer`
2. **BUG** replicas are accepting ops from sources different from what is inside the Op's Dot.

We don't have a test case for 2. yet, TODO: add a property that would catch this.
