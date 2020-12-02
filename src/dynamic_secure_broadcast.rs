use crate::actor::Actor;
use std::collections::BTreeSet;

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

#[derive(Debug, PartialEq, Eq)]
enum Error {
    ReconfigInProgress {
        generation: u64,
        pending_generation: u64,
    },
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

    fn reconfig(&self, reconfig: Reconfig) -> Result<Vec<Packet>, Error> {
        self.ensure_no_reconfig_in_progress()?;

        let vote = Vote {
            voter: self.id,
            ballot: Ballot::Initiate(reconfig),
            generation: self.generation + 1,
        };

        let packets: Vec<Packet> = self
            .members
            .iter()
            .cloned()
            .map(|member| Packet {
                vote: vote.clone(),
                source: self.id,
                dest: member,
            })
            .collect();

        Ok(packets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crdts::quickcheck::{quickcheck, TestResult};

    #[test]
    fn test_reject_new_reconfig_if_one_in_progress() {
        let mut proc = Proc::default();
        proc.pending_generation += 1;
        assert_eq!(
            proc.reconfig(Reconfig::Join(Actor::generate().0)),
            Err(Error::ReconfigInProgress {
                generation: 0,
                pending_generation: 1
            })
        );
    }
}
