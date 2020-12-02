use crate::actor::Actor;
use std::collections::BTreeSet;

const MAX_MEMBERS: usize = 7;

#[derive(Debug)]
struct Proc {
    id: Actor,
    generation: u64,
    pending_generation: u64,
    members: BTreeSet<Actor>,
}

impl Default for Proc {
    fn default() -> Self {
        let (actor, _keypair) = Actor::generate();

        Self {
            id: actor,
            generation: 0,
            pending_generation: 0,
            members: Default::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Reconfig {
    Join(Actor),
    Leave(Actor),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Ballot {
    Initiate(Reconfig),
    SplitVote(BTreeSet<Vote>),
    Quorum(BTreeSet<Vote>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Vote {
    voter: Actor,
    ballot: Ballot,
    generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Packet {
    vote: Vote,
    source: Actor,
    dest: Actor,
}

#[derive(Debug, PartialEq, Eq)]
enum Error {
    ReconfigInProgress {
        generation: u64,
        pending_generation: u64,
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
}

impl Proc {
    fn ensure_no_reconfig_in_progress(&self) -> Result<(), Error> {
        if self.generation != self.pending_generation {
            Err(Error::ReconfigInProgress {
                generation: self.generation,
                pending_generation: self.pending_generation,
            })
        } else {
            Ok(())
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
                } else if self.members.len() == MAX_MEMBERS {
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
                source: self.id,
                dest: member,
            })
            .collect()
    }

    fn reconfig(&self, reconfig: Reconfig) -> Result<Vec<Packet>, Error> {
        self.ensure_no_reconfig_in_progress()?;
        self.validate_reconfig(&reconfig)?;

        let vote = Vote {
            voter: self.id,
            ballot: Ballot::Initiate(reconfig),
            generation: self.generation + 1,
        };

        Ok(self.broadcast(vote))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crdts::quickcheck::{quickcheck, TestResult};

    #[test]
    fn test_reject_new_reconfig_if_one_in_progress() {
        let proc = Proc {
            generation: 0,
            pending_generation: 1,
            ..Proc::default()
        };

        assert_eq!(
            proc.reconfig(Reconfig::Join(Actor::generate().0)),
            Err(Error::ReconfigInProgress {
                generation: 0,
                pending_generation: 1
            })
        );
    }

    #[test]
    fn test_reject_new_join_if_we_are_at_capacity() {
        let proc = Proc {
            members: (0..7).map(|_| Actor::generate().0).collect(),
            ..Proc::default()
        };

        assert_eq!(
            proc.reconfig(Reconfig::Join(Actor::generate().0)),
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
        let proc = Proc {
            members: (0..1).map(|_| Actor::generate().0).collect(),
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
        let proc = Proc {
            members: (0..1).map(|_| Actor::generate().0).collect(),
            ..Proc::default()
        };

        let leaving_actor = Actor::generate().0;
        assert_eq!(
            proc.reconfig(Reconfig::Leave(leaving_actor)),
            Err(Error::LeaveRequestForNonMember {
                requester: leaving_actor,
                members: proc.members.clone(),
            })
        );
    }
}
