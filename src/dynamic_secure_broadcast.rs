use std::collections::BTreeSet;

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
    sig: Sig,
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
    VoteFromPreviousGeneration {
        vote_gen: Generation,
        gen: Generation,
    },
}

impl Proc {
    pub fn trust(&mut self, actor: Actor) {
        self.members.insert(actor);
    }

    pub fn reconfig(&mut self, reconfig: Reconfig) -> Result<Vec<Packet>, Error> {
        self.adopt_ballot(Ballot::Propose(reconfig))
    }

    pub fn adopt_ballot(&mut self, ballot: Ballot) -> Result<Vec<Packet>, Error> {
        self.ensure_no_reconfig_in_progress()?;
        self.validate_ballot(&ballot)?;

        self.pending_gen = self.gen + 1;

        let gen = self.pending_gen;
        let sig = self.id.sign((&ballot, &gen));
        let vote = Vote { ballot, gen, sig };

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
            self.adopt_ballot(vote.ballot.clone())
        } else if self.pending_gen == vote.gen {
            Err(Error::NotImplemented)
        } else {
            Err(Error::NotImplemented)
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
        let Packet {
            source,
            dest,
            vote: Vote { gen, ballot, sig },
        } = packet;

        if !source.verify((&ballot, &gen), sig) {
            Err(Error::InvalidSignature)
        } else if dest != &self.id.actor() {
            Err(Error::WrongDestination {
                dest: *dest,
                actor: self.id.actor(),
            })
        } else if *gen <= self.gen {
            Err(Error::VoteFromPreviousGeneration {
                vote_gen: *gen,
                gen: self.gen,
            })
        } else {
            Err(Error::NotImplemented)
        }
    }

    fn validate_ballot(&self, ballot: &Ballot) -> Result<(), Error> {
        match ballot {
            Ballot::Propose(reconfig) => self.validate_reconfig(&reconfig),
            Ballot::Merge(votes) => Err(Error::NotImplemented),
            Ballot::Quorum(votes) => Err(Error::NotImplemented),
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

        proc.gen += 1; // move to the next gen

        assert_eq!(
            proc.handle_packet(packets.pop().unwrap()),
            Err(Error::VoteFromPreviousGeneration {
                vote_gen: 1,
                gen: 1,
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

        let resp = proc.handle_packet(Packet {
            source: source.actor(),
            dest,
            vote: Vote { ballot, gen, sig },
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
        let sig = SigningActor::default().sign((&ballot, &gen));
        let resp = proc.handle_packet(Packet {
            source: Default::default(),
            dest: proc.id.actor(),
            vote: Vote { ballot, gen, sig },
        });

        assert_eq!(resp, Err(Error::InvalidSignature));
    }

    quickcheck! {
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
