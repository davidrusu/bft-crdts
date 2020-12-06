#[cfg(test)]
mod tests {

    use std::collections::{BTreeMap, BTreeSet};

    use crdts::quickcheck::{quickcheck, TestResult};
    use serde::Serialize;

    use crate::actor::{Actor, Sig, SigningActor};

    const SOFT_MAX_MEMBERS: usize = 7;
    type Generation = u64;

    #[derive(Debug, Default)]
    struct Proc {
        id: SigningActor,
        gen: Generation,
        pending_gen: Generation,
        members: BTreeSet<Actor>,
        votes: BTreeMap<Actor, Vote>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
    enum Reconfig {
        Join(Actor),
        Leave(Actor),
    }

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
    enum Ballot {
        Propose(Reconfig),
        Merge(BTreeSet<Vote>),
        Quorum(BTreeSet<Vote>),
    }

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
    struct Vote {
        gen: Generation,
        ballot: Ballot,
        voter: Actor,
        sig: Sig,
    }

    impl Vote {
        fn is_quorum(&self) -> bool {
            match self.ballot {
                Ballot::Quorum(_) => true,
                _ => false,
            }
        }

        fn round(&self) -> usize {
            match &self.ballot {
                Ballot::Propose(_) => 1,
                Ballot::Merge(votes) | Ballot::Quorum(votes) => {
                    assert!(!votes.is_empty());
                    votes.iter().map(|v| v.round()).max().unwrap() + 1
                }
            }
        }

        fn reconfigs(&self) -> BTreeSet<(Actor, Reconfig)> {
            match &self.ballot {
                Ballot::Propose(reconfig) => {
                    vec![(self.voter, reconfig.clone())].into_iter().collect()
                }
                Ballot::Merge(votes) | Ballot::Quorum(votes) => {
                    votes.iter().flat_map(|v| v.reconfigs()).collect()
                }
            }
        }

        fn has_seen(&self, vote: &Vote) -> bool {
            if self == vote {
                true
            } else {
                match &self.ballot {
                    Ballot::Propose(_) => false,
                    Ballot::Merge(votes) | Ballot::Quorum(votes) => {
                        votes.iter().any(|v| v.has_seen(vote))
                    }
                }
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Packet {
        vote: Vote,
        source: Actor,
        dest: Actor,
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Error {
        InvalidSignature,
        WrongDestination {
            dest: Actor,
            actor: Actor,
        },
        MembersAtCapacity {
            members: BTreeSet<Actor>,
        },
        JoinRequestForExistingMember {
            requester: Actor,
            members: BTreeSet<Actor>,
        },
        LeaveRequestForNonMember {
            requester: Actor,
            members: BTreeSet<Actor>,
        },
        VoteNotForThisGeneration {
            vote_gen: Generation,
            gen: Generation,
            pending_gen: Generation,
        },
        VoteFromNonMember {
            voter: Actor,
            members: BTreeSet<Actor>,
        },
        VoterChangedMind {
            reconfigs: BTreeSet<(Actor, Reconfig)>,
        },
        ExistingVoteFromVoterIsNotPresentInNewVote,
    }

    impl Proc {
        pub fn trust(&mut self, actor: Actor) {
            self.members.insert(actor);
        }

        pub fn reconfig(&mut self, reconfig: Reconfig) -> Result<Vec<Packet>, Error> {
            self.adopt_ballot(self.gen + 1, Ballot::Propose(reconfig))
        }

        pub fn adopt_ballot(
            &mut self,
            gen: Generation,
            ballot: Ballot,
        ) -> Result<Vec<Packet>, Error> {
            assert!(self.gen == gen || self.gen + 1 == gen);

            let sig = self.id.sign((&ballot, &gen));
            let voter = self.id.actor();
            let vote = Vote {
                ballot,
                gen,
                voter,
                sig,
            };

            self.validate_vote(&vote)?;

            self.pending_gen = gen;
            self.votes.insert(self.id.actor(), vote.clone());
            Ok(self.broadcast(vote))
        }

        pub fn handle_packet(&mut self, packet: Packet) -> Result<Vec<Packet>, Error> {
            self.validate_packet(&packet)?;
            let Packet { vote, .. } = packet;

            if self.pending_gen + 1 == vote.gen {
                assert_eq!(self.votes, Default::default());
                // A gen change has begun but this is the first we're hearing of it. Adopt the vote (if we agree with it)
                self.votes.insert(vote.voter, vote.clone());
                self.adopt_ballot(vote.gen, vote.ballot.clone())
            } else if self.pending_gen == vote.gen {
                // This is a vote from the current generation change
                assert_eq!(self.gen + 1, self.pending_gen);

                // we must have voted to be in this state
                assert!(self.votes.contains_key(&self.id.actor()));

                self.votes.insert(vote.voter, vote);

                if self.is_split_vote() {
                    println!("[DSB] Detected split vote");
                    // We've detected that we can't form quorum
                    self.adopt_ballot(
                        self.pending_gen,
                        Ballot::Merge(self.votes.values().cloned().collect()),
                    )
                } else if self.is_quorum() {
                    // we have quorum.. but over what?
                    if self.is_quorum_over_quorums() {
                        println!("[DSB] Detected quorum over quorum");
                        // The network has come to agreement, apply the reconfigs.
                        for reconfig in self.resolve_votes() {
                            self.apply(reconfig);
                        }
                        Ok(vec![])
                    } else {
                        println!("[DSB] Detected quorum");
                        self.adopt_ballot(
                            self.pending_gen,
                            Ballot::Quorum(self.votes.values().cloned().collect()),
                        )
                    }
                } else {
                    // still waiting for more votes
                    Ok(vec![])
                }
            } else {
                panic!("Not Implemented");
            }
        }

        fn apply(&mut self, reconfig: Reconfig) {
            match reconfig {
                Reconfig::Join(peer) => self.members.insert(peer),
                Reconfig::Leave(peer) => self.members.remove(&peer),
            };
        }

        fn count_votes(&self) -> BTreeMap<BTreeSet<Reconfig>, usize> {
            let round = self
                .votes
                .values()
                .map(|v| v.round())
                .max()
                .unwrap_or_default();

            let mut count: BTreeMap<BTreeSet<Reconfig>, usize> = Default::default();

            for vote in self.votes.values().filter(|v| v.round() == round) {
                let c = count
                    .entry(
                        vote.reconfigs()
                            .into_iter()
                            .map(|(_, reconfig)| reconfig)
                            .collect(),
                    )
                    .or_default();
                *c += 1;
            }

            count
        }

        fn is_split_vote(&self) -> bool {
            let counts = self.count_votes();
            let total_votes: usize = counts.values().sum();
            let most_votes = counts.values().max().cloned().unwrap_or_default();
            let n = self.members.len();
            let outstanding_votes = n - total_votes;
            let predicted_votes = most_votes + outstanding_votes;

            3 * total_votes > 2 * n && 3 * predicted_votes <= 2 * n
        }

        fn is_quorum(&self) -> bool {
            let most_votes = self
                .count_votes()
                .values()
                .max()
                .cloned()
                .unwrap_or_default();
            let n = self.members.len();

            3 * most_votes > 2 * n
        }

        fn is_quorum_over_quorums(&self) -> bool {
            let winning_reconfigs = self.resolve_votes();

            let count_of_quorums = self
                .votes
                .values()
                .filter(|v| {
                    v.reconfigs()
                        .into_iter()
                        .map(|(_, r)| r)
                        .collect::<BTreeSet<_>>()
                        == winning_reconfigs
                })
                .filter(|v| v.is_quorum())
                .count();

            3 * count_of_quorums > 2 * self.members.len()
        }

        fn resolve_votes(&self) -> BTreeSet<Reconfig> {
            let (winning_reconfigs, _) = self
                .count_votes()
                .into_iter()
                .max_by(|a, b| (a.1).cmp(&b.1))
                .unwrap_or_default();

            winning_reconfigs
        }

        fn validate_packet(&self, packet: &Packet) -> Result<(), Error> {
            let Packet { source, dest, vote } = packet;

            if dest != &self.id.actor() {
                Err(Error::WrongDestination {
                    dest: *dest,
                    actor: self.id.actor(),
                })
            } else if *source != vote.voter {
                panic!(
                    "Packet source different from voter, not sure if this is allowed {:#?}",
                    packet
                );
            } else {
                self.validate_vote(vote)
            }
        }

        fn validate_vote(&self, vote: &Vote) -> Result<(), Error> {
            if !vote.voter.verify((&vote.ballot, &vote.gen), &vote.sig) {
                Err(Error::InvalidSignature)
            } else if !self.members.contains(&vote.voter) {
                Err(Error::VoteFromNonMember {
                    voter: vote.voter,
                    members: self.members.clone(),
                })
            } else if self.votes.contains_key(&vote.voter)
                && !vote.has_seen(&self.votes[&vote.voter])
            {
                Err(Error::ExistingVoteFromVoterIsNotPresentInNewVote)
            } else if vote.gen == self.gen + 1 && self.pending_gen == self.gen {
                // We are starting a vote for the next generation
                assert_eq!(self.votes, Default::default()); // we should not have any votes yet
                self.validate_ballot(vote.gen, &vote.ballot)
            } else if self.pending_gen == self.gen + 1 && vote.gen == self.pending_gen {
                // This is a vote for this generation
                assert_ne!(self.votes, Default::default(), "{:?} {:#?}", vote, self); // we should have at least one vote

                // Ensure that nobody is trying to change their reconfig's.
                let reconfigs: BTreeSet<(Actor, Reconfig)> = self
                    .votes
                    .values()
                    .flat_map(|v| v.reconfigs())
                    .chain(vote.reconfigs())
                    .collect();

                let voters: BTreeSet<Actor> = reconfigs.iter().map(|(actor, _)| *actor).collect();
                if voters.len() != reconfigs.len() {
                    assert!(voters.len() > reconfigs.len());
                    Err(Error::VoterChangedMind { reconfigs })
                } else {
                    self.validate_ballot(vote.gen, &vote.ballot)
                }
            } else if vote.gen <= self.gen || vote.gen > self.pending_gen {
                Err(Error::VoteNotForThisGeneration {
                    vote_gen: vote.gen,
                    gen: self.gen,
                    pending_gen: self.pending_gen,
                })
            } else {
                panic!("Unhandled case {:?} {:#?}", vote, self);
            }
        }

        fn validate_ballot(&self, gen: Generation, ballot: &Ballot) -> Result<(), Error> {
            match ballot {
                Ballot::Propose(reconfig) => self.validate_reconfig(&reconfig),
                Ballot::Merge(_votes) => panic!("validate(Merge) not implemented"),
                Ballot::Quorum(_votes) => panic!("validate(Quorum) not implemented"),
            }
        }

        fn validate_reconfig(&self, reconfig: &Reconfig) -> Result<(), Error> {
            match reconfig {
                Reconfig::Join(actor) => {
                    if self.members.contains(&actor) {
                        Err(Error::JoinRequestForExistingMember {
                            requester: *actor,
                            members: self.members.clone(),
                        })
                    } else if self.members.len() >= SOFT_MAX_MEMBERS {
                        Err(Error::MembersAtCapacity {
                            members: self.members.clone(),
                        })
                    } else {
                        Ok(())
                    }
                }
                Reconfig::Leave(actor) => {
                    if !self.members.contains(&actor) {
                        Err(Error::LeaveRequestForNonMember {
                            requester: *actor,
                            members: self.members.clone(),
                        })
                    } else {
                        Ok(())
                    }
                }
            }
        }

        fn broadcast(&self, vote: Vote) -> Vec<Packet> {
            self.members
                .iter()
                .cloned()
                .map(|member| Packet {
                    vote: vote.clone(),
                    source: self.id.actor(),
                    dest: member,
                })
                .collect()
        }
    }

    #[test]
    fn test_reject_changing_reconfig_when_one_is_in_progress() {
        let mut proc = Proc::default();
        proc.trust(proc.id.actor());
        assert!(proc.reconfig(Reconfig::Join(Actor::default())).is_ok());
        assert_eq!(
            proc.reconfig(Reconfig::Join(Actor::default())),
            Err(Error::ExistingVoteFromVoterIsNotPresentInNewVote)
        );
    }

    #[test]
    fn test_reject_vote_from_non_member() {
        let mut net = Net::with_procs(2);
        let p0 = net.procs[0].id.actor();
        let p1 = net.procs[1].id.actor();
        net.trust(p1, p0);
        net.trust(p1, p1);

        let resp = net.procs[1].reconfig(Reconfig::Join(Default::default()));
        assert!(resp.is_ok());
        net.queue_packets(resp.unwrap());
        net.drain_queued_packets();
    }

    #[test]
    fn test_reject_new_join_if_we_are_at_capacity() {
        let mut proc = Proc {
            members: (0..7).map(|_| Actor::default()).collect(),
            ..Proc::default()
        };
        proc.trust(proc.id.actor());

        assert_eq!(
            proc.reconfig(Reconfig::Join(Actor::default())),
            Err(Error::MembersAtCapacity {
                members: proc.members.clone()
            })
        );

        assert!(proc
            .reconfig(Reconfig::Leave(proc.members.iter().next().unwrap().clone()))
            .is_ok())
    }

    #[test]
    fn test_reject_join_if_actor_is_already_a_member() {
        let mut proc = Proc {
            members: (0..1).map(|_| Actor::default()).collect(),
            ..Proc::default()
        };
        proc.trust(proc.id.actor());

        let member = proc.members.iter().next().unwrap().clone();

        assert_eq!(
            proc.reconfig(Reconfig::Join(member)),
            Err(Error::JoinRequestForExistingMember {
                requester: member,
                members: proc.members.clone(),
            })
        );
    }

    #[test]
    fn test_reject_leave_if_actor_is_not_a_member() {
        let mut proc = Proc {
            members: (0..1).map(|_| Actor::default()).collect(),
            ..Proc::default()
        };
        proc.trust(proc.id.actor());

        let leaving_actor = Actor::default();
        assert_eq!(
            proc.reconfig(Reconfig::Leave(leaving_actor)),
            Err(Error::LeaveRequestForNonMember {
                requester: leaving_actor,
                members: proc.members.clone(),
            })
        );
    }

    #[test]
    fn test_handle_packet_rejects_packet_from_previous_gen() {
        let mut proc = Proc::default();
        proc.trust(proc.id.actor()); // trust self

        let mut packets = proc.reconfig(Reconfig::Join(Actor::default())).unwrap();
        assert_eq!(packets.len(), 1);

        // move to the next gen
        proc.gen += 1;

        assert_eq!(
            proc.handle_packet(packets.pop().unwrap()),
            Err(Error::VoteNotForThisGeneration {
                vote_gen: 1,
                gen: 1,
                pending_gen: 1,
            })
        );
    }

    #[test]
    fn test_reject_packets_not_destined_for_proc() {
        let mut proc = Proc::default();

        let ballot = Ballot::Propose(Reconfig::Join(Default::default()));
        let gen = proc.gen + 1;
        let source = SigningActor::default();
        let dest = Default::default();
        let sig = source.sign((&ballot, &gen));
        let voter = source.actor();

        let resp = proc.handle_packet(Packet {
            source: voter,
            dest,
            vote: Vote {
                ballot,
                gen,
                voter,
                sig,
            },
        });

        assert_eq!(
            resp,
            Err(Error::WrongDestination {
                dest,
                actor: proc.id.actor()
            })
        );
    }

    #[test]
    fn test_reject_packets_with_invalid_signatures() {
        let mut proc = Proc::default();
        let ballot = Ballot::Propose(Reconfig::Join(Default::default()));
        let gen = proc.gen + 1;
        let voter = Default::default();
        let sig = SigningActor::default().sign((&ballot, &gen));
        let resp = proc.handle_packet(Packet {
            source: voter,
            dest: proc.id.actor(),
            vote: Vote {
                ballot,
                gen,
                voter,
                sig,
            },
        });

        assert_eq!(resp, Err(Error::InvalidSignature));
    }

    #[derive(Default, Debug)]
    struct Net {
        procs: Vec<Proc>,
        expected_members: BTreeMap<Actor, BTreeSet<Actor>>,
        pending_reconfigs: BTreeSet<Reconfig>,
        packets: BTreeMap<Actor, Vec<Packet>>,
    }

    impl Net {
        fn with_procs(n: usize) -> Self {
            Self {
                procs: (0..n).into_iter().map(|_| Proc::default()).collect(),
                ..Default::default()
            }
        }

        fn genesis(&self) -> Actor {
            assert!(!self.procs.is_empty());
            self.procs[0].id.actor()
        }

        fn deliver_packet_from_source(&mut self, source: Actor) {
            let packet = if let Some(packets) = self.packets.get_mut(&source) {
                assert!(packets.len() > 0);
                packets.remove(0)
            } else {
                return;
            };

            self.packets = self
                .packets
                .clone()
                .into_iter()
                .filter(|(_, queue)| !queue.is_empty())
                .collect();

            assert_eq!(packet.source, source);

            let dest_proc = self
                .procs
                .iter_mut()
                .find(|p| p.id.actor() == packet.dest)
                .unwrap();

            let dest_members = self.expected_members.entry(packet.dest).or_default();
            match dest_proc.handle_packet(packet) {
                Ok(resp_packets) => {
                    // A process only accepts a packet if it considers the sender a member
                    assert!(dest_members.contains(&source));

                    // TODO: inspect these packets
                    assert!(resp_packets
                        .iter()
                        .all(|p| p.source == dest_proc.id.actor()));
                    self.queue_packets(resp_packets);
                }
                Err(Error::VoteFromNonMember { voter, members }) => {
                    assert_eq!(voter, source);
                    assert_eq!(members, dest_members.clone());
                    assert!(!dest_members.contains(&source));
                }
                Err(err) => {
                    panic!("Unexpected err: {:?} {:#?}", err, self);
                }
            }
        }

        fn queue_packets(&mut self, packets: impl IntoIterator<Item = Packet>) {
            for packet in packets {
                self.packets.entry(packet.source).or_default().push(packet);
            }
        }

        fn drain_queued_packets(&mut self) {
            while self.packets.len() > 0 {
                let source = self.packets.keys().next().unwrap().clone();
                self.deliver_packet_from_source(source);
            }
        }

        fn trust(&mut self, p: Actor, q: Actor) {
            if let Some(proc) = self.procs.iter_mut().find(|proc| proc.id.actor() == p) {
                proc.trust(q);
                self.expected_members.entry(p).or_default().insert(q);
            }
        }
    }

    quickcheck! {
        fn prop_interpreter(n: u8, instructions: Vec<(u8, u8, u8)>) -> TestResult {
            fn quorum(m: usize, n: usize) -> bool {
                3 * m > 2 * n
            }

            if n == 0 || n > 7 {
                return TestResult::discard();
            }

            println!("--------------------------------------");

            let mut net = Net::with_procs(n as usize);

            // Assume procs[0] is the genesis proc. (trusts itself)
            let gen_proc = net.genesis();
            for proc in net.procs.iter_mut() {
                proc.trust(gen_proc);
                net.expected_members.entry(proc.id.actor()).or_default().insert(gen_proc);
            }


            for instruction in instructions {
                println!("{:#?}", net);
                match instruction {
                    (0, source_idx, _) => {
                        // deliver packet
                        let source = net.procs[source_idx.min(n -1) as usize].id.actor();
                        net.deliver_packet_from_source(source);
                    }
                    (1, p_idx, q_idx) => {
                        // p requests to join q
                        let p = net.procs[p_idx.min(n - 1) as usize].id.actor();
                        let reconfig = Reconfig::Join(p);

                        let q = &mut net.procs[q_idx.min(n - 1) as usize];
                        match q.reconfig(reconfig.clone()) {
                            Ok(reconfig_packets) => {
                                net.pending_reconfigs.insert(reconfig);
                                assert!(reconfig_packets.iter().all(|p| p.source == q.id.actor()));
                                net.queue_packets(reconfig_packets);
                            }
                            Err(Error::JoinRequestForExistingMember { .. }) => {
                                assert!(net.expected_members[&q.id.actor()].contains(&p));
                            }
                            Err(Error::VoteFromNonMember { .. }) => {
                                assert!(!net.expected_members[&q.id.actor()].contains(&q.id.actor()));
                            }
                            Err(err) => {
                                // invalid request.
                                panic!("Failure to reconfig is not handled yet: {:?}", err);
                            }
                        }
                    }
                    _ => {}
                }
            }

            println!("{:#?}", net);
            println!("--  [DRAINING]  --");
            net.drain_queued_packets();
            println!("{:#?}", net);

            let mut procs_by_gen: BTreeMap<Generation, Vec<Proc>> = Default::default();

            for proc in net.procs {
                procs_by_gen.entry(proc.gen).or_default().push(proc);
            }

            let max_gen = procs_by_gen.keys().last().unwrap();

            // The last gen should have at least a quorum of nodes
            assert!(quorum(procs_by_gen[max_gen].len(), n as usize));

            // And procs at each generation should have agreement on members
            for (_, procs) in procs_by_gen {
                let mut proc_iter = procs.iter();
                let first = proc_iter.next().unwrap();
                for proc in proc_iter {
                    assert_eq!(first.members, proc.members);
                }
            }

            assert_eq!(net.pending_reconfigs, Default::default());

            // ensure all procs are in the same generations
            // ensure all procs agree on the same
            TestResult::passed()
        }

        fn prop_validate_reconfig(join_or_leave: bool, actor_idx: usize, members: u8) -> TestResult {
            if members + 1 > 7 {
                // + 1 from the initial proc
                return TestResult::discard();
            }

            let mut proc = Proc::default();

            let trusted_actors: Vec<_> = (0..members)
                .map(|_| Actor::default())
                .chain(vec![proc.id.actor()])
                .collect();

            for a in trusted_actors.iter() {
                proc.trust(*a);
            }

            let all_actors = {
                let mut actors = trusted_actors.clone();
                actors.push(Actor::default());
                actors
            };

            let actor = all_actors[actor_idx % all_actors.len()];
            let reconfig = match join_or_leave {
                true => Reconfig::Join(actor),
                false => Reconfig::Leave(actor),
            };

            let valid_res = proc.validate_reconfig(&reconfig);
            match reconfig {
                Reconfig::Join(actor) => {
                    if proc.members.contains(&actor) {
                        assert_eq!(
                            valid_res,
                            Err(Error::JoinRequestForExistingMember {
                                requester: actor,
                                members: proc.members.clone()
                            })
                        );
                    } else if members + 1 == 7 {
                        assert_eq!(
                            valid_res,
                            Err(Error::MembersAtCapacity {
                                members: proc.members.clone()
                            })
                        );
                    } else {
                        assert_eq!(valid_res, Ok(()));
                    }
                }
                Reconfig::Leave(actor) => {
                    if proc.members.contains(&actor) {
                        assert_eq!(valid_res, Ok(()));
                    } else {
                        assert_eq!(valid_res, Err(Error::LeaveRequestForNonMember {
                            requester: actor,
                            members: trusted_actors.into_iter().collect(),
                        }));

                    }
                }
            };

            TestResult::passed()
        }
    }
}
