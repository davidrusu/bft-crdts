use std::collections::{BTreeMap, BTreeSet};

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
    votes: BTreeSet<Vote>,
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
    fn reconfigs(&self) -> BTreeSet<(Actor, Reconfig)> {
        match &self.ballot {
            Ballot::Propose(reconfig) => vec![(self.voter, reconfig.clone())].into_iter().collect(),
            Ballot::Merge(votes) | Ballot::Quorum(votes) => {
                votes.iter().flat_map(|v| v.reconfigs()).collect()
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
    NotImplemented,
    InvalidSignature,
    WrongDestination {
        dest: Actor,
        actor: Actor,
    },
    ReconfigInProgress {
        gen: Generation,
        pending_gen: Generation,
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
}

impl Proc {
    pub fn trust(&mut self, actor: Actor) {
        self.members.insert(actor);
    }

    pub fn reconfig(&mut self, reconfig: Reconfig) -> Result<Vec<Packet>, Error> {
        self.adopt_ballot(self.gen + 1, Ballot::Propose(reconfig))
    }

    pub fn adopt_ballot(&mut self, gen: Generation, ballot: Ballot) -> Result<Vec<Packet>, Error> {
        self.ensure_no_reconfig_in_progress()?;
        self.validate_ballot(gen, &ballot)?;
        assert!(self.gen == gen || self.gen + 1 == gen);
        self.pending_gen = gen;

        let gen = self.pending_gen;
        let sig = self.id.sign((&ballot, &gen));
        let voter = self.id.actor();
        let vote = Vote {
            ballot,
            gen,
            voter,
            sig,
        };

        self.votes.insert(vote.clone());

        Ok(self.broadcast(vote))
    }

    pub fn handle_packet(&mut self, packet: Packet) -> Result<Vec<Packet>, Error> {
        self.validate_packet(&packet)?;
        let Packet { vote, source, dest } = packet;

        if self.pending_gen + 1 == vote.gen {
            assert_eq!(self.votes, Default::default());
            // A gen change has begun but this is the first we're hearing of it. Adopt the vote (if we agree with it)
            self.votes.insert(vote.clone());
            self.adopt_ballot(vote.gen, vote.ballot.clone())
        } else if self.pending_gen == vote.gen {
            // This is a vote from the current generation change
            assert_eq!(self.gen + 1, self.pending_gen);
            panic!("Not Implemented");
        } else {
            panic!("Not Implemented");
        }
    }

    fn ensure_no_reconfig_in_progress(&self) -> Result<(), Error> {
        if self.gen != self.pending_gen {
            Err(Error::ReconfigInProgress {
                gen: self.gen,
                pending_gen: self.pending_gen,
            })
        } else {
            Ok(())
        }
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
        } else if vote.gen == self.gen + 1 && self.pending_gen == self.gen {
            // We are starting a vote for the next generation
            assert_eq!(self.votes, Default::default()); // we should not have any votes yet
            self.validate_ballot(vote.gen, &vote.ballot)
        } else if self.pending_gen == self.gen + 1 && vote.gen == self.pending_gen {
            // This is a vote for this generation
            assert_ne!(self.votes, Default::default()); // we should have at least one vote

            // Ensure that nobody is trying to change their reconfig's.
            let reconfigs: BTreeSet<(Actor, Reconfig)> = self
                .votes
                .iter()
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
            Ballot::Merge(votes) => panic!("validate(Merge) not implemented"),
            Ballot::Quorum(votes) => panic!("validate(Quorum) not implemented"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crdts::quickcheck::{quickcheck, TestResult};

    #[test]
    fn test_reject_new_reconfig_if_one_in_progress() {
        let mut proc = Proc {
            gen: 0,
            pending_gen: 1,
            ..Proc::default()
        };

        assert_eq!(
            proc.reconfig(Reconfig::Join(Actor::default())),
            Err(Error::ReconfigInProgress {
                gen: 0,
                pending_gen: 1
            })
        );
    }

    #[test]
    fn test_reject_new_join_if_we_are_at_capacity() {
        let mut proc = Proc {
            members: (0..7).map(|_| Actor::default()).collect(),
            ..Proc::default()
        };

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

    quickcheck! {
        fn prop_interpreter(n: u8, instructions: Vec<(u8, u8, u8)>) -> TestResult {
            fn quorum(m: usize, n: usize) -> bool {
                3 * m > 2 * n
            }

            if n == 0 || n > 7 {
                return TestResult::discard();
            }

            let mut procs: Vec<Proc> = (0..n).into_iter().map(|_| Proc::default()).collect();
            let mut members_per_proc: BTreeMap<Actor, BTreeSet<Actor>> = Default::default();

            // Assume procs[0] is the genesis proc. (trusts itself)
            let gen_actor = procs[0].id.actor();
            for proc in procs.iter_mut() {
                proc.trust(gen_actor);
                members_per_proc.entry(proc.id.actor()).or_default().insert(gen_actor);
            }
            let mut packets: BTreeMap<Actor, Vec<Packet>> = Default::default();
            for instruction in instructions {
                match instruction {
                    (0, source_idx, _) => {
                        // deliver packet
                        let source = procs[source_idx.min(n -1) as usize].id.actor();
                        if let Some(mut packets_from_source) = packets.remove(&source) {
                            let packet = packets_from_source.remove(0);
                            if packets_from_source.len() > 0 {
                                packets.insert(source, packets_from_source);
                            }

                            let dest = packet.dest;

                            let p = procs
                                .iter_mut()
                                .find(|p| p.id.actor() == dest)
                                .unwrap();

                            let resp = p.handle_packet(packet);

                            // this process should not have accepted this packet if it does not consider it a member

                            let dest_members = members_per_proc.entry(dest).or_default();
                            if dest_members.contains(&source) {
                                assert!(resp.is_ok())
                            } else {
                                assert_eq!(
                                    resp,
                                    Err(Error::VoteFromNonMember{ voter: source, members: dest_members.clone() })
                                )
                            }
                            match resp {
                                Ok(resp_packets) =>  {
                                    packets.entry(p.id.actor()).or_default().extend(resp_packets)
                                }
                                Err(err) => {
                                    assert!(false, "{:?}", err);
                                }
                            }
                        }
                    }
                    (1, p_idx, q_idx) => {
                        // p requests to join q
                        let p = &procs[p_idx.min(n - 1) as usize];
                        let reconfig = Reconfig::Join(p.id.actor());

                        let q = &mut procs[q_idx.min(n - 1) as usize];
                        if let Ok(reconfig_packets) = q.reconfig(reconfig) {
                            packets.entry(q.id.actor()).or_default().extend(reconfig_packets);
                        } else {
                            // invalid request.
                           // TODO: charactize the types of failures that may occur here.
                        }
                    }
                    _ => {}
                }
            }

            while let Some(source) = packets.keys().next().cloned() {
                let mut source_packets = packets.remove(&source).unwrap();
                let packet = source_packets.remove(0);
                assert_eq!(packet.source, source);

                if source_packets.len() > 0 {
                    packets.insert(source, source_packets);
                }

                let p = procs
                    .iter_mut()
                    .find(|p| p.id.actor() == packet.dest)
                    .unwrap();

                if let Ok(resp_packets) = p.handle_packet(packet) {
                    packets.entry(p.id.actor()).or_default().extend(resp_packets)
                } else {
                    // TODO: characterize failures
                }
            }

            let mut procs_by_gen: BTreeMap<Generation, Vec<Proc>> = Default::default();

            for proc in procs {
                procs_by_gen.entry(proc.gen).or_default().push(proc);
            }

            let max_gen = procs_by_gen.keys().last().unwrap();

            // The last gen should have at least a quorum of nodes
            assert!(quorum(procs_by_gen[max_gen].len(), n as usize));

            // And procs at each generation should have agreement on members
            for (gen, procs) in procs_by_gen {
                let mut proc_iter = procs.iter();
                let first = proc_iter.next().unwrap();
                for proc in proc_iter {
                    assert_eq!(first.members, proc.members);
                }
            }

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
