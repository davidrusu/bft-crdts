use std::collections::{HashMap, HashSet};

use crate::actor::Actor;
use crate::deterministic_secure_broadcast::{Packet, SecureBroadcastProc};
use crate::traits::SecureBroadcastAlgorithm;

#[derive(Debug)]
pub struct Net<A: SecureBroadcastAlgorithm> {
    pub procs: Vec<SecureBroadcastProc<A>>,
    pub n_packets: u64,
}

impl<A: SecureBroadcastAlgorithm> Net<A> {
    pub fn new() -> Self {
        Self {
            procs: Vec::new(),
            n_packets: 0,
        }
    }

    /// The largest set of procs who mutually see each other as peers
    /// are considered to be the network members.
    pub fn members(&self) -> HashSet<Actor> {
        self.procs
            .iter()
            .map(|proc| {
                proc.peers()
                    .iter()
                    .flat_map(|peer| self.proc_from_actor(peer))
                    .filter(|peer_proc| peer_proc.peers().contains(&proc.actor()))
                    .map(|peer_proc| peer_proc.actor())
                    .collect::<HashSet<_>>()
            })
            .max_by_key(|members| members.len())
            .unwrap_or_default()
    }

    /// Fetch the actors for each process in the network
    pub fn actors(&self) -> HashSet<Actor> {
        self.procs.iter().map(|p| p.actor()).collect()
    }

    /// Initialize a new process (NOTE: we do not request membership from the network automatically)
    pub fn initialize_proc(&mut self) -> Actor {
        let proc = SecureBroadcastProc::new(self.members());
        let actor = proc.actor();
        self.procs.push(proc);
        actor
    }

    /// Execute arbitrary code on a proc (immutable)
    pub fn on_proc<V>(
        &self,
        actor: &Actor,
        f: impl FnOnce(&SecureBroadcastProc<A>) -> V,
    ) -> Option<V> {
        self.proc_from_actor(actor).map(|p| f(p))
    }

    /// Execute arbitrary code on a proc (mutating)
    pub fn on_proc_mut<V>(
        &mut self,
        actor: &Actor,
        f: impl FnOnce(&mut SecureBroadcastProc<A>) -> V,
    ) -> Option<V> {
        self.proc_from_actor_mut(actor).map(|p| f(p))
    }

    /// Get a (immutable) reference to a proc with the given actor.
    pub fn proc_from_actor(&self, actor: &Actor) -> Option<&SecureBroadcastProc<A>> {
        self.procs
            .iter()
            .find(|secure_p| &secure_p.actor() == actor)
    }

    /// Get a (mutable) reference to a proc with the given actor.
    pub fn proc_from_actor_mut(&mut self, actor: &Actor) -> Option<&mut SecureBroadcastProc<A>> {
        self.procs
            .iter_mut()
            .find(|secure_p| &secure_p.actor() == actor)
    }

    /// Perform anti-entropy corrections on the network.
    /// Currently this is God mode implementations in that we don't
    /// use message passing and we share process state directly.
    pub fn anti_entropy(&mut self) {
        // TODO: this should be done through a message passing interface.

        // For each proc, collect the procs who considers this proc it's peer.
        let mut peer_reverse_index: HashMap<Actor, HashSet<Actor>> = HashMap::new();

        for proc in self.procs.iter() {
            for peer in proc.peers() {
                peer_reverse_index
                    .entry(peer)
                    .or_default()
                    .insert(proc.actor());
            }
        }

        for (proc_actor, reverse_peers) in peer_reverse_index {
            // other procs that consider this proc a peer, will share there state with this proc
            for reverse_peer in reverse_peers {
                let source_peer_state = self.proc_from_actor(&reverse_peer).unwrap().state();
                self.on_proc_mut(&proc_actor, |p| p.sync_from(source_peer_state));
                println!("[TEST_NET] {} -> {}", reverse_peer, proc_actor);
            }
        }
    }

    /// Delivers a given packet to it's target recipiant.
    /// The recipiant, upon processing this packet, may produce it's own packets.
    /// This next set of packets are returned to the caller.
    pub fn deliver_packet(&mut self, packet: Packet<A::Op>) -> Vec<Packet<A::Op>> {
        println!("[NET] packet {}->{}", packet.source, packet.dest);
        self.n_packets += 1;
        self.on_proc_mut(&packet.dest.clone(), |p| p.handle_packet(packet))
            .unwrap_or_default()
    }

    /// Checks if all members of the network have converged to the same state.
    pub fn members_are_in_agreement(&self) -> bool {
        let mut member_states_iter = self
            .members()
            .into_iter()
            .flat_map(|actor| self.proc_from_actor(&actor))
            .map(|p| p.state());

        if let Some(reference_state) = member_states_iter.next() {
            member_states_iter.all(|s| s == reference_state)
        } else {
            true // vacuously, there are no members
        }
    }

    /// Convenience function to iteratively deliver all packets along with any packets
    /// that may result from delivering a packet.
    pub fn run_packets_to_completion(&mut self, mut packets: Vec<Packet<A::Op>>) {
        while let Some(packet) = packets.pop() {
            packets.extend(self.deliver_packet(packet));
        }
    }
}
