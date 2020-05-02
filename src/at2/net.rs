use std::collections::{HashMap, HashSet};

use crate::at2::deterministic_secure_broadcast::{Packet, SecureBroadcastProc};
use crate::at2::identity::Identity;
use crate::at2::traits::SecureBroadcastAlgorithm;

#[derive(Debug)]
pub struct Net<A: SecureBroadcastAlgorithm> {
    pub procs: Vec<SecureBroadcastProc<A>>, // TODO: profile and make this a Map<Identity, SecureBroadcastProc> if it's too slow
    pub n_packets: u64,
}

impl<A: SecureBroadcastAlgorithm> Net<A> {
    pub fn new() -> Self {
        Self {
            procs: Vec::new(),
            n_packets: 0,
        }
    }

    pub fn members(&self) -> HashSet<Identity> {
        // the largest subset of procs that mutually see each other as peers
        self.procs
            .iter()
            .map(|proc| {
                proc.peers()
                    .iter()
                    .flat_map(|peer| self.proc_from_id(peer))
                    .filter(|peer_proc| peer_proc.peers().contains(&proc.identity()))
                    .map(|peer_proc| peer_proc.identity())
                    .collect::<HashSet<_>>()
            })
            .max_by_key(|members| members.len())
            .unwrap_or_default()
    }

    pub fn initialize_proc(&mut self) -> Identity {
        let proc = SecureBroadcastProc::new(self.members());
        let id = proc.identity();
        self.procs.push(proc);
        id
    }

    pub fn on_proc<V>(
        &self,
        id: &Identity,
        f: impl FnOnce(&SecureBroadcastProc<A>) -> V,
    ) -> Option<V> {
        self.proc_from_id(id).map(|p| f(p))
    }

    pub fn on_proc_mut<V>(
        &mut self,
        id: &Identity,
        f: impl FnOnce(&mut SecureBroadcastProc<A>) -> V,
    ) -> Option<V> {
        self.proc_from_id_mut(id).map(|p| f(p))
    }

    // TODO: inline these two methods if they continue to only be used by `on_proc*`
    pub fn proc_from_id(&self, id: &Identity) -> Option<&SecureBroadcastProc<A>> {
        self.procs
            .iter()
            .find(|secure_p| &secure_p.identity() == id)
    }

    pub fn proc_from_id_mut(&mut self, id: &Identity) -> Option<&mut SecureBroadcastProc<A>> {
        self.procs
            .iter_mut()
            .find(|secure_p| &secure_p.identity() == id)
    }

    pub fn anti_entropy(&mut self) {
        // TODO: this should be done through a message(packet) passing interface.
        println!("[TEST_NET] anti_entropy");

        // For each proc, collect the procs who considers this proc it's peer.
        let mut peer_reverse_index: HashMap<Identity, HashSet<Identity>> = HashMap::new();

        for proc in self.procs.iter() {
            for peer in proc.peers() {
                peer_reverse_index
                    .entry(peer)
                    .or_default()
                    .insert(proc.identity());
            }
        }

        for (proc_id, reverse_peers) in peer_reverse_index {
            // other procs that consider this proc a peer, will share there state with this proc
            for reverse_peer in reverse_peers {
                let source_peer_state = self.proc_from_id(&reverse_peer).unwrap().state();
                self.on_proc_mut(&proc_id, |p| p.sync_from(source_peer_state));
                println!("[TEST_NET] {} -> {}", reverse_peer, proc_id);
            }
        }
    }

    pub fn identities(&self) -> HashSet<Identity> {
        self.procs.iter().map(|p| p.identity()).collect()
    }

    pub fn deliver_packet(&mut self, packet: Packet<A::Op>) -> Vec<Packet<A::Op>> {
        println!("[NET] packet {}->{}", packet.source, packet.dest);
        self.n_packets += 1;
        self.on_proc_mut(&packet.dest.clone(), |p| p.handle_packet(packet))
            .unwrap_or_default()
    }

    pub fn members_are_in_agreement(&self) -> bool {
        let mut member_states_iter = self
            .members()
            .into_iter()
            .flat_map(|id| self.proc_from_id(&id))
            .map(|p| p.state());

        if let Some(reference_state) = member_states_iter.next() {
            member_states_iter.all(|s| s == reference_state)
        } else {
            true
        }
    }

    pub fn run_packets_to_completion(&mut self, mut packets: Vec<Packet<A::Op>>) {
        while let Some(packet) = packets.pop() {
            packets.extend(self.deliver_packet(packet));
        }
    }
}
