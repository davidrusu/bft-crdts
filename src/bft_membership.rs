use std::collections::{BTreeMap, BTreeSet};

use bincode;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::actor::{Actor, Sig, SigningActor};
use crate::packet::{Packet, Payload};

const SOFT_MAX_MEMBERS: usize = 7;
pub type Generation = u64;

#[derive(Debug, Default)]
pub struct State {
    pub id: SigningActor,
    pub gen: Generation,
    pub pending_gen: Generation,
    trusted_members: BTreeSet<Actor>,
    pub history: BTreeMap<Generation, Vote>, // for onboarding new procs, the vote proving super majority
    pub votes: BTreeMap<Actor, Vote>,
    pub faulty: bool,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Reconfig {
    Join(Actor),
    Leave(Actor),
}

impl std::fmt::Debug for Reconfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reconfig::Join(a) => write!(f, "J{:?}", a),
            Reconfig::Leave(a) => write!(f, "L{:?}", a),
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Ballot {
    Propose(Reconfig),
    Merge(BTreeSet<Vote>),
    SuperMajority(BTreeSet<Vote>),
}

impl std::fmt::Debug for Ballot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ballot::Propose(r) => write!(f, "P({:?})", r),
            Ballot::Merge(votes) => write!(f, "M{:?}", votes),
            Ballot::SuperMajority(votes) => write!(f, "SM{:?}", votes),
        }
    }
}

fn simplify_votes(votes: &BTreeSet<Vote>) -> BTreeSet<Vote> {
    let mut simpler_votes: BTreeSet<Vote> = Default::default();
    for v in votes.iter() {
        let mut this_vote_is_superseded = false;
        for other_v in votes.iter() {
            if other_v != v && other_v.supersedes(&v) {
                this_vote_is_superseded = true;
            }
        }

        if !this_vote_is_superseded {
            simpler_votes.insert(v.clone());
        }
    }
    simpler_votes
}

impl Ballot {
    fn simplify(&self) -> Self {
        match &self {
            Ballot::Propose(_) => self.clone(), // already in simplest form
            Ballot::Merge(votes) => Ballot::Merge(simplify_votes(&votes)),
            Ballot::SuperMajority(votes) => Ballot::SuperMajority(simplify_votes(&votes)),
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Vote {
    gen: Generation,
    ballot: Ballot,
    voter: Actor,
    sig: Sig,
}

impl std::fmt::Debug for Vote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}@{}G{}", self.ballot, self.voter, self.gen)
    }
}

impl Vote {
    fn is_super_majority_ballot(&self) -> bool {
        matches!(self.ballot, Ballot::SuperMajority(_))
    }

    fn unpack_votes(&self) -> BTreeSet<&Vote> {
        match &self.ballot {
            Ballot::Propose(_) => std::iter::once(self).collect(),
            Ballot::Merge(votes) | Ballot::SuperMajority(votes) => std::iter::once(self)
                .chain(votes.iter().flat_map(|v| v.unpack_votes()))
                .collect(),
        }
    }

    fn reconfigs(&self) -> BTreeSet<(Actor, Reconfig)> {
        match &self.ballot {
            Ballot::Propose(reconfig) => vec![(self.voter, reconfig.clone())].into_iter().collect(),
            Ballot::Merge(votes) | Ballot::SuperMajority(votes) => {
                votes.iter().flat_map(|v| v.reconfigs()).collect()
            }
        }
    }

    fn supersedes(&self, vote: &Vote) -> bool {
        if self == vote {
            true
        } else {
            match &self.ballot {
                Ballot::Propose(_) => false,
                Ballot::Merge(votes) | Ballot::SuperMajority(votes) => {
                    votes.iter().any(|v| v.supersedes(vote))
                }
            }
        }
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Vote has an invalid signature")]
    InvalidSignature,
    #[error("Packet was not destined for this actor: {dest} != {actor}")]
    WrongDestination { dest: Actor, actor: Actor },
    #[error(
        "We can not accept any new join requests, network member size is at capacity: {members:?}"
    )]
    MembersAtCapacity { members: BTreeSet<Actor> },
    #[error(
        "An existing member `{requester}` can not request to join again. (members: {members:?})"
    )]
    JoinRequestForExistingMember {
        requester: Actor,
        members: BTreeSet<Actor>,
    },
    #[error("You must be a member to request to leave ({requester} not in {members:?})")]
    LeaveRequestForNonMember {
        requester: Actor,
        members: BTreeSet<Actor>,
    },
    #[error("A vote is always for the next generation: vote gen {vote_gen} != {gen} + 1")]
    VoteNotForNextGeneration {
        vote_gen: Generation,
        gen: Generation,
        pending_gen: Generation,
    },
    #[error("Vote from non member ({voter} not in {members:?})")]
    VoteFromNonMember {
        voter: Actor,
        members: BTreeSet<Actor>,
    },
    #[error("Voter changed their mind: {reconfigs:?}")]
    VoterChangedMind {
        reconfigs: BTreeSet<(Actor, Reconfig)>,
    },
    #[error("Existing vote {existing_vote:?} not compatible with new vote: {vote:?}")]
    ExistingVoteIncompatibleWithNewVote { vote: Vote, existing_vote: Vote },
    #[error("The super majority ballot does not actually have supermajority: {ballot:?} (members: {members:?})")]
    SuperMajorityBallotIsNotSuperMajority {
        ballot: Ballot,
        members: BTreeSet<Actor>,
    },
    #[error("Invalid generation {0}")]
    InvalidGeneration(Generation),
    #[error("History contains an invalid vote {0:?}")]
    InvalidVoteInHistory(Vote),
    #[error("Failed to encode with bincode")]
    Encoding(#[from] bincode::Error),
}

impl State {
    pub fn trust(&mut self, actor: Actor) {
        self.trusted_members.insert(actor);
    }

    pub fn members(&self, gen: Generation) -> Result<BTreeSet<Actor>, Error> {
        let mut members = self.trusted_members.clone();
        if gen == 0 {
            return Ok(members);
        }

        for (history_gen, vote) in self.history.iter() {
            let votes = match &vote.ballot {
                Ballot::SuperMajority(votes) => votes,
                _ => {
                    return Err(Error::InvalidVoteInHistory(vote.clone()));
                }
            };
            for reconfig in self.resolve_votes(votes) {
                match reconfig {
                    Reconfig::Join(m) => members.insert(m),
                    Reconfig::Leave(m) => members.remove(&m),
                };
            }

            if history_gen == &gen {
                return Ok(members);
            }
        }

        Err(Error::InvalidGeneration(gen))
    }

    pub fn propose<T: Serialize>(&mut self, reconfig: Reconfig) -> Result<Vec<Packet<T>>, Error> {
        let vote = self.build_vote(self.gen + 1, Ballot::Propose(reconfig))?;
        self.cast_vote(vote)
    }

    pub fn handle_vote<T: Serialize>(&mut self, vote: Vote) -> Result<Vec<Packet<T>>, Error> {
        self.validate_vote(&vote)?;

        self.log_vote(&vote);
        self.pending_gen = vote.gen;

        if self.is_split_vote(&self.votes.values().cloned().collect())? {
            println!("[DSB] Detected split vote");
            let merge_vote = self.build_vote(
                self.pending_gen,
                Ballot::Merge(self.votes.values().cloned().collect()).simplify(),
            )?;

            if let Some(our_vote) = self.votes.get(&self.id.actor()) {
                let reconfigs_we_voted_for: BTreeSet<_> =
                    our_vote.reconfigs().into_iter().map(|(_, r)| r).collect();
                let reconfigs_we_would_vote_for: BTreeSet<_> =
                    merge_vote.reconfigs().into_iter().map(|(_, r)| r).collect();

                if reconfigs_we_voted_for == reconfigs_we_would_vote_for {
                    println!(
                        "[DSB] This vote didn't add new information, waiting for more votes..."
                    );
                    return Ok(vec![]);
                }
            }

            println!("[DSB] Either we haven't voted or our previous vote didn't fully overlap, merge them.");
            return self.cast_vote(merge_vote);
        }

        if self.is_super_majority_over_super_majorities(&self.votes.values().cloned().collect())? {
            println!("[DSB] Detected super majority over super majorities");
            let we_were_a_member_during_this_generation =
                self.members(self.gen)?.contains(&self.id.actor());

            let reconfigs_we_agreed_to =
                self.resolve_votes(&self.votes.values().cloned().collect());

            self.gen = self.pending_gen;

            // store a proof of what the network decided in our history so that we can onboard future procs.
            let ballot = Ballot::SuperMajority(self.votes.values().cloned().collect()).simplify();
            let vote = Vote {
                voter: self.id.actor(),
                sig: self.id.sign((&ballot, &self.gen))?,
                gen: self.gen,
                ballot,
            };
            self.history.insert(self.gen, vote.clone());

            // clear our pending votes
            self.votes = Default::default();

            if we_were_a_member_during_this_generation {
                // Figure out which procs we need to onboard.
                let new_members: BTreeSet<Actor> = reconfigs_we_agreed_to
                    .into_iter()
                    .filter_map(|r| match r {
                        Reconfig::Join(p) => Some(p),
                        Reconfig::Leave(_) => None,
                    })
                    .collect();

                return new_members
                    .into_iter()
                    .flat_map(|p| {
                        // deliver the history in order from gen=1 onwards
                        self.history
                            .iter() // history is a BTreeSet, .iter() is ordered by generation
                            .map(|(_gen, membership_proof)| self.send(membership_proof.clone(), p))
                            .collect::<Vec<Result<_, _>>>()
                    })
                    .collect::<Result<Vec<_>, Error>>();
            } else {
                return Ok(vec![]);
            }
        }

        if self.is_super_majority(&self.votes.values().cloned().collect())? {
            println!("[DSB] Detected super majority");

            if let Some(our_vote) = self.votes.get(&self.id.actor()) {
                // We voted during this generation.

                // We may have committed to some reconfigs that is not part of this super majority.
                // This happens when the network was able to form super majority without our vote.
                // We can not change our vote since all we know is that a subset of the network saw
                // super majority. It could still be the case that two disjoint subsets of the network
                // see different super majorities, this case will be resolved by the split vote detection
                // as more packets are delivered.

                let super_majority_reconfigs =
                    self.resolve_votes(&self.votes.values().cloned().collect());

                let we_have_comitted_to_reconfigs_not_in_super_majority = self
                    .resolve_votes(&our_vote.unpack_votes().into_iter().cloned().collect())
                    .into_iter()
                    .filter(|r| !super_majority_reconfigs.contains(r))
                    .next()
                    .is_some();

                if we_have_comitted_to_reconfigs_not_in_super_majority {
                    println!("[DSB] We have committed to reconfigs that the super majority has not seen, waiting till we either have a split vote or SM/SM");
                    return Ok(vec![]);
                } else if our_vote.is_super_majority_ballot() {
                    println!("[DSB] We've already sent a super majority, waiting till we either have a split vote or SM / SM");
                    return Ok(vec![]);
                }
            }

            println!("[DSB] broadcasting super majority");
            let vote = self.build_vote(
                self.pending_gen,
                Ballot::SuperMajority(self.votes.values().cloned().collect()).simplify(),
            )?;
            return self.cast_vote(vote);
        }

        // We have determined that we don't yet have enough votes to take action.
        // If we have not yet voted, this is where we would contribute our vote
        if !self.votes.contains_key(&self.id.actor()) {
            // vote with all pending reconfigs
            let vote = self.build_vote(self.pending_gen, vote.ballot.clone())?;
            return self.cast_vote(vote);
        }

        Ok(vec![])
    }

    fn build_vote(&self, gen: Generation, ballot: Ballot) -> Result<Vote, Error> {
        Ok(Vote {
            voter: self.id.actor(),
            sig: self.id.sign((&ballot, &gen))?,
            ballot,
            gen,
        })
    }

    fn cast_vote<T: Serialize>(&mut self, vote: Vote) -> Result<Vec<Packet<T>>, Error> {
        self.validate_vote(&vote)?;
        self.pending_gen = vote.gen;
        self.log_vote(&vote);
        self.broadcast(vote)
    }

    fn log_vote(&mut self, vote: &Vote) {
        for vote in vote.unpack_votes() {
            let existing_vote = self.votes.entry(vote.voter).or_insert_with(|| vote.clone());
            if vote.supersedes(&existing_vote) {
                *existing_vote = vote.clone()
            }
        }
    }

    fn count_votes(&self, votes: &BTreeSet<Vote>) -> BTreeMap<BTreeSet<Reconfig>, usize> {
        let mut count: BTreeMap<BTreeSet<Reconfig>, usize> = Default::default();

        for vote in votes.iter() {
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

    fn is_split_vote(&self, votes: &BTreeSet<Vote>) -> Result<bool, Error> {
        let counts = self.count_votes(votes);
        let votes_received: usize = counts.values().sum();
        let most_votes = counts.values().max().cloned().unwrap_or_default();
        let n = self.members(self.gen)?.len();
        let outstanding_votes = n - votes_received;
        let predicted_votes = most_votes + outstanding_votes;

        Ok(3 * votes_received > 2 * n && 3 * predicted_votes <= 2 * n)
    }

    fn is_super_majority(&self, votes: &BTreeSet<Vote>) -> Result<bool, Error> {
        // TODO: super majority should always just be the largest 7 members
        let most_votes = self
            .count_votes(votes)
            .values()
            .max()
            .cloned()
            .unwrap_or_default();
        let n = self.members(self.gen)?.len();

        Ok(3 * most_votes > 2 * n)
    }

    fn is_super_majority_over_super_majorities(
        &self,
        votes: &BTreeSet<Vote>,
    ) -> Result<bool, Error> {
        let winning_reconfigs = self.resolve_votes(votes);

        let count_of_super_majorities = votes
            .iter()
            .filter(|v| {
                v.reconfigs()
                    .into_iter()
                    .map(|(_, r)| r)
                    .collect::<BTreeSet<_>>()
                    == winning_reconfigs
            })
            .filter(|v| v.is_super_majority_ballot())
            .count();

        Ok(3 * count_of_super_majorities > 2 * self.members(self.gen)?.len())
    }

    fn resolve_votes(&self, votes: &BTreeSet<Vote>) -> BTreeSet<Reconfig> {
        let (winning_reconfigs, _) = self
            .count_votes(votes)
            .into_iter()
            .max_by(|a, b| (a.1).cmp(&b.1))
            .unwrap_or_default();

        winning_reconfigs
    }

    fn validate_vote(&self, vote: &Vote) -> Result<(), Error> {
        let members = self.members(self.gen)?;
        if !vote.voter.verify((&vote.ballot, &vote.gen), &vote.sig)? {
            Err(Error::InvalidSignature)
        } else if vote.gen != self.gen + 1 {
            Err(Error::VoteNotForNextGeneration {
                vote_gen: vote.gen,
                gen: self.gen,
                pending_gen: self.pending_gen,
            })
        } else if !members.contains(&vote.voter) {
            Err(Error::VoteFromNonMember {
                voter: vote.voter,
                members,
            })
        } else if self.votes.contains_key(&vote.voter)
            && !vote.supersedes(&self.votes[&vote.voter])
            && !self.votes[&vote.voter].supersedes(&vote)
        {
            Err(Error::ExistingVoteIncompatibleWithNewVote {
                vote: vote.clone(),
                existing_vote: self.votes[&vote.voter].clone(),
            })
        } else if self.pending_gen == self.gen {
            // We are starting a vote for the next generation
            self.validate_ballot(vote.gen, &vote.ballot)
        } else {
            // This is a vote for this generation

            // Ensure that nobody is trying to change their reconfig's.
            let reconfigs: BTreeSet<(Actor, Reconfig)> = self
                .votes
                .values()
                .flat_map(|v| v.reconfigs())
                .chain(vote.reconfigs())
                .collect();

            let voters: BTreeSet<Actor> = reconfigs.iter().map(|(actor, _)| *actor).collect();
            if voters.len() != reconfigs.len() {
                Err(Error::VoterChangedMind { reconfigs })
            } else {
                self.validate_ballot(vote.gen, &vote.ballot)
            }
        }
    }

    fn validate_ballot(&self, gen: Generation, ballot: &Ballot) -> Result<(), Error> {
        match ballot {
            Ballot::Propose(reconfig) => self.validate_reconfig(&reconfig),
            Ballot::Merge(votes) => {
                for vote in votes.iter() {
                    if vote.gen != gen {
                        return Err(Error::VoteNotForNextGeneration {
                            vote_gen: vote.gen,
                            gen: gen,
                            pending_gen: gen,
                        });
                    }
                    self.validate_vote(vote)?;
                }
                Ok(())
            }
            Ballot::SuperMajority(votes) => {
                let members = self.members(self.gen)?;
                if !self.is_super_majority(
                    &votes
                        .iter()
                        .flat_map(|v| v.unpack_votes())
                        .cloned()
                        .collect(),
                )? {
                    Err(Error::SuperMajorityBallotIsNotSuperMajority {
                        ballot: ballot.clone(),
                        members: members,
                    })
                } else {
                    for vote in votes.iter() {
                        if vote.gen != gen {
                            return Err(Error::VoteNotForNextGeneration {
                                vote_gen: vote.gen,
                                gen: gen,
                                pending_gen: gen,
                            });
                        }
                        self.validate_vote(vote)?;
                    }
                    Ok(())
                }
            }
        }
    }

    fn validate_reconfig(&self, reconfig: &Reconfig) -> Result<(), Error> {
        let members = self.members(self.gen)?;
        match reconfig {
            Reconfig::Join(actor) => {
                if members.contains(&actor) {
                    Err(Error::JoinRequestForExistingMember {
                        requester: *actor,
                        members: members,
                    })
                } else if members.len() >= SOFT_MAX_MEMBERS {
                    Err(Error::MembersAtCapacity { members: members })
                } else {
                    Ok(())
                }
            }
            Reconfig::Leave(actor) => {
                if !members.contains(&actor) {
                    Err(Error::LeaveRequestForNonMember {
                        requester: *actor,
                        members: members,
                    })
                } else {
                    Ok(())
                }
            }
        }
    }

    fn broadcast<T: Serialize>(&self, vote: Vote) -> Result<Vec<Packet<T>>, Error> {
        self.members(self.gen)?
            .iter()
            .cloned()
            .map(|member| self.send(vote.clone(), member))
            .collect()
    }

    fn send<T: Serialize>(&self, vote: Vote, dest: Actor) -> Result<Packet<T>, Error> {
        let source = self.id.actor();
        let payload = Payload::Membership(vote);
        let sig = self.id.sign(&payload)?;
        Ok(Packet {
            source,
            dest,
            payload,
            sig,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    use crdts::quickcheck::{quickcheck, Arbitrary, Gen, TestResult};

    #[derive(Default, Debug)]
    pub struct Net {
        pub procs: Vec<State>,
        pub reconfigs_by_gen: BTreeMap<Generation, BTreeSet<Reconfig>>,
        pub members_at_gen: BTreeMap<Generation, BTreeSet<Actor>>,
        pub packets: BTreeMap<Actor, Vec<Packet<()>>>,
        pub delivered_packets: Vec<Packet<()>>,
    }

    impl Net {
        pub fn with_procs(n: usize) -> Self {
            let mut procs: Vec<_> = (0..n).into_iter().map(|_| State::default()).collect();
            procs.sort_by_key(|p| p.id.actor());
            Self {
                procs,
                ..Default::default()
            }
        }

        pub fn genesis(&self) -> Actor {
            assert!(!self.procs.is_empty());
            self.procs[0].id.actor()
        }

        pub fn deliver_packet_from_source(&mut self, source: Actor) {
            let packet = if let Some(packets) = self.packets.get_mut(&source) {
                assert!(packets.len() > 0);
                packets.remove(0)
            } else {
                return;
            };

            let dest = packet.dest;

            assert_eq!(packet.source, source);

            println!(
                "delivering {:?}->{:?} {:#?}",
                packet.source, packet.dest, packet
            );

            self.delivered_packets.push(packet.clone());

            self.packets = self
                .packets
                .clone()
                .into_iter()
                .filter(|(_, queue)| !queue.is_empty())
                .collect();

            assert_eq!(packet.source, source);

            let dest_proc_opt = self.procs.iter_mut().find(|p| p.id.actor() == packet.dest);

            let dest_proc = match dest_proc_opt {
                Some(proc) => proc,
                None => {
                    println!("[NET] destination proc does not exist, dropping packet");
                    return;
                }
            };

            let dest_members = dest_proc.members(dest_proc.gen).unwrap();
            let vote = match packet.payload {
                Payload::Membership(vote) => vote,
                _ => panic!("Unexpected payload type"),
            };

            let resp = dest_proc.handle_vote(vote);
            println!("[NET] resp: {:#?}", resp);
            match resp {
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
                    assert_eq!(voter, source, "{:?} not in {:?}", voter, members);
                    assert_eq!(members, dest_members.clone());
                    assert!(!dest_members.contains(&source));
                }
                Err(Error::VoteNotForNextGeneration {
                    vote_gen,
                    gen,
                    pending_gen,
                }) => {
                    assert!(vote_gen <= gen || vote_gen > pending_gen);
                    assert_eq!(dest_proc.gen, gen);
                    assert_eq!(dest_proc.pending_gen, pending_gen);
                }
                Err(err) => {
                    panic!("Unexpected err: {:?} {:?}", err, self);
                }
            }

            let proc = self.procs.iter().find(|p| p.id.actor() == dest).unwrap();
            if !proc.faulty {
                let (mut proc_members, gen) = (proc.members(proc.gen).unwrap().clone(), proc.gen);

                let expected_members_at_gen = self
                    .members_at_gen
                    .entry(gen)
                    .or_insert(proc_members.clone());

                assert_eq!(expected_members_at_gen, &mut proc_members);
            }
        }

        pub fn queue_packets(&mut self, packets: impl IntoIterator<Item = Packet<()>>) {
            for packet in packets {
                self.packets.entry(packet.source).or_default().push(packet);
            }
        }

        pub fn drain_queued_packets(&mut self) {
            while self.packets.len() > 0 {
                let source = self.packets.keys().next().unwrap().clone();
                self.deliver_packet_from_source(source);
            }
        }

        pub fn trust(&mut self, p: Actor, q: Actor) {
            if let Some(proc) = self.procs.iter_mut().find(|proc| proc.id.actor() == p) {
                proc.trust(q);
            }
        }

        pub fn generate_msc(&self) -> String {
            // See: http://www.mcternan.me.uk/mscgen/
            let mut msc = String::from(
                "
msc {\n
  hscale = \"2\";\n
",
            );
            let procs = self
                .procs
                .iter()
                .map(|p| p.id.actor())
                .collect::<BTreeSet<_>>() // sort by actor id
                .into_iter()
                .map(|id| format!("{:?}", id))
                .collect::<Vec<_>>()
                .join(",");
            msc.push_str(&procs);
            msc.push_str(";\n");
            for packet in self.delivered_packets.iter() {
                msc.push_str(&format!(
                    "{} -> {} [ label=\"{:?}\"];\n",
                    packet.source,
                    packet.dest,
                    match &packet.payload {
                        Payload::Membership(v) => v,
                        _ => panic!("invalid payload"),
                    }
                ));
            }

            msc.push_str("}\n");

            // Replace process identifiers with friendlier numbers
            // 1, 2, 3 ... instead of i:3b2, i:7def, ...
            for (idx, proc_id) in self.procs.iter().map(|p| p.id.actor()).enumerate() {
                let proc_id_as_str = format!("{}", proc_id);
                msc = msc.replace(&proc_id_as_str, &format!("{}", idx + 1));
            }

            msc
        }
    }

    #[test]
    fn test_reject_changing_reconfig_when_one_is_in_progress() {
        let mut proc = State::default();
        proc.trust(proc.id.actor());
        assert!(proc.propose::<()>(Reconfig::Join(Actor::default())).is_ok());
        assert!(matches!(
            proc.propose::<()>(Reconfig::Join(Actor::default())),
            Err(Error::ExistingVoteIncompatibleWithNewVote { .. })
        ));
    }

    #[test]
    fn test_reject_vote_from_non_member() {
        let mut net = Net::with_procs(2);
        net.procs[1].faulty = true;
        let p0 = net.procs[0].id.actor();
        let p1 = net.procs[1].id.actor();
        net.trust(p1, p0);
        net.trust(p1, p1);

        let resp = net.procs[1].propose(Reconfig::Join(Default::default()));
        assert!(resp.is_ok());
        net.queue_packets(resp.unwrap());
        net.drain_queued_packets();
    }

    #[test]
    fn test_reject_new_join_if_we_are_at_capacity() {
        let mut proc = State {
            trusted_members: (0..7).map(|_| Actor::default()).collect(),
            ..State::default()
        };
        proc.trust(proc.id.actor());

        assert!(matches!(
            proc.propose::<()>(Reconfig::Join(Actor::default())),
            Err(Error::MembersAtCapacity { .. })
        ));

        assert!(proc
            .propose::<()>(Reconfig::Leave(
                proc.members(proc.gen).unwrap().into_iter().next().unwrap()
            ))
            .is_ok())
    }

    #[test]
    fn test_reject_join_if_actor_is_already_a_member() {
        let mut proc = State {
            trusted_members: (0..1).map(|_| Actor::default()).collect(),
            ..State::default()
        };
        proc.trust(proc.id.actor());

        let member = proc.members(proc.gen).unwrap().into_iter().next().unwrap();
        assert!(matches!(
            proc.propose::<()>(Reconfig::Join(member)),
            Err(Error::JoinRequestForExistingMember { .. })
        ));
    }

    #[test]
    fn test_reject_leave_if_actor_is_not_a_member() {
        let mut proc = State {
            trusted_members: (0..1).map(|_| Actor::default()).collect(),
            ..State::default()
        };
        proc.trust(proc.id.actor());

        let leaving_actor = Actor::default();
        assert!(matches!(
            proc.propose::<()>(Reconfig::Leave(leaving_actor)),
            Err(Error::LeaveRequestForNonMember { .. })
        ));
    }

    #[test]
    fn test_handle_vote_rejects_packet_from_previous_gen() {
        let mut net = Net::with_procs(2);
        let a_0 = net.procs[0].id.actor();
        let a_1 = net.procs[1].id.actor();
        net.procs[0].trust(a_0);
        net.procs[0].trust(a_1);
        net.procs[1].trust(a_0);
        net.procs[1].trust(a_1);

        let packets = net.procs[0]
            .propose::<()>(Reconfig::Join(Actor::default()))
            .unwrap();
        let mut stale_packets = net.procs[1]
            .propose::<()>(Reconfig::Join(Actor::default()))
            .unwrap();
        net.procs[1].pending_gen = 0;
        net.procs[1].votes = Default::default();

        assert_eq!(packets.len(), 2); // two members in the network
        assert_eq!(stale_packets.len(), 2);

        net.queue_packets(packets);
        net.drain_queued_packets();

        println!("net: {:#?}", net);
        let vote = match stale_packets.pop().unwrap().payload {
            Payload::Membership(vote) => vote,
            _ => panic!("Unexpected payload type"),
        };

        assert!(matches!(
            net.procs[0].handle_vote::<()>(vote),
            Err(Error::VoteNotForNextGeneration {
                vote_gen: 1,
                gen: 1,
                pending_gen: 1,
            })
        ));
    }

    #[test]
    fn test_reject_votes_with_invalid_signatures() {
        let mut proc = State::default();
        let ballot = Ballot::Propose(Reconfig::Join(Default::default()));
        let gen = proc.gen + 1;
        let voter = Default::default();
        let sig = SigningActor::default().sign((&ballot, &gen)).unwrap();
        let resp = proc.handle_vote::<()>(Vote {
            ballot,
            gen,
            voter,
            sig,
        });

        assert!(matches!(resp, Err(Error::InvalidSignature)));
    }

    #[test]
    fn test_split_vote() {
        for nprocs in 1..7 {
            let mut net = Net::with_procs(nprocs * 2);
            for i in 0..nprocs {
                let i_actor = net.procs[i].id.actor();
                for j in 0..(nprocs * 2) {
                    net.procs[j].trust(i_actor);
                }
            }

            let joining_members: Vec<Actor> =
                net.procs[nprocs..].iter().map(|p| p.id.actor()).collect();
            for i in 0..nprocs {
                let member = joining_members[i];
                let packets = net.procs[i].propose(Reconfig::Join(member)).unwrap();
                net.queue_packets(packets);
            }

            net.drain_queued_packets();

            let mut msc_file = File::create(format!("split_vote_{}.msc", nprocs)).unwrap();
            msc_file.write_all(net.generate_msc().as_bytes()).unwrap();

            let proc0_gen = net.procs[0].gen;
            let expected_members = net.procs[0].members(proc0_gen).unwrap();
            assert!(expected_members.len() > nprocs);

            for i in 0..nprocs {
                let proc_i_gen = net.procs[i].gen;
                assert_eq!(proc_i_gen, proc0_gen);
                assert_eq!(net.procs[i].members(proc_i_gen).unwrap(), expected_members);
            }

            for member in expected_members.iter() {
                let p = net.procs.iter().find(|p| &p.id.actor() == member).unwrap();
                assert_eq!(p.members(p.gen).unwrap(), expected_members);
            }
        }
    }

    #[test]
    fn test_round_robin_split_vote() {
        for nprocs in 1..7 {
            let mut net = Net::with_procs(nprocs * 2);
            for i in 0..nprocs {
                let i_actor = net.procs[i].id.actor();
                for j in 0..(nprocs * 2) {
                    net.procs[j].trust(i_actor);
                }
            }

            let joining_members: Vec<Actor> =
                net.procs[nprocs..].iter().map(|p| p.id.actor()).collect();
            for i in 0..nprocs {
                let member = joining_members[i];
                let packets = net.procs[i].propose(Reconfig::Join(member)).unwrap();
                net.queue_packets(packets);
            }

            while !net.packets.is_empty() {
                println!("{:?}", net);
                for i in 0..net.procs.len() {
                    net.deliver_packet_from_source(net.procs[i].id.actor());
                }
            }

            let mut msc_file =
                File::create(format!("round_robin_split_vote_{}.msc", nprocs)).unwrap();
            msc_file.write_all(net.generate_msc().as_bytes()).unwrap();

            let proc_0_gen = net.procs[0].gen;
            let expected_members = net.procs[0].members(proc_0_gen).unwrap();
            assert!(expected_members.len() > nprocs);

            for i in 0..nprocs {
                let gen = net.procs[i].gen;
                assert_eq!(net.procs[i].members(gen).unwrap(), expected_members);
            }

            for member in expected_members.iter() {
                let p = net.procs.iter().find(|p| &p.id.actor() == member).unwrap();
                assert_eq!(p.members(p.gen).unwrap(), expected_members);
            }
        }
    }

    #[test]
    fn test_onboarding_across_many_generations() {
        let mut net = Net::with_procs(3);
        let p0 = net.procs[0].id.actor();
        let p1 = net.procs[1].id.actor();
        let p2 = net.procs[2].id.actor();

        for i in 0..3 {
            net.procs[i].trust(p0);
        }
        let packets = net.procs[0].propose(Reconfig::Join(p1)).unwrap();
        net.queue_packets(packets);
        net.deliver_packet_from_source(p0);
        net.deliver_packet_from_source(p0);
        let packets = net.procs[0].propose(Reconfig::Join(p2)).unwrap();
        net.queue_packets(packets);
        net.drain_queued_packets();

        let mut procs_by_gen: BTreeMap<Generation, Vec<State>> = Default::default();

        let mut msc_file = File::create("onboarding.msc").unwrap();
        msc_file.write_all(net.generate_msc().as_bytes()).unwrap();

        for proc in net.procs {
            procs_by_gen.entry(proc.gen).or_default().push(proc);
        }

        let max_gen = procs_by_gen.keys().last().unwrap();
        // The last gen should have at least a super majority of nodes
        let current_members: BTreeSet<_> =
            procs_by_gen[max_gen].iter().map(|p| p.id.actor()).collect();

        for proc in procs_by_gen[max_gen].iter() {
            assert_eq!(current_members, proc.members(proc.gen).unwrap());
        }
    }

    #[test]
    fn test_simple_proposal() {
        let mut net = Net::with_procs(4);
        for i in 0..4 {
            let a_i = net.procs[i].id.actor();
            for j in 0..3 {
                let a_j = net.procs[j].id.actor();
                net.trust(a_i, a_j);
            }
        }

        let proc_3 = net.procs[3].id.actor();
        let packets = net.procs[0].propose(Reconfig::Join(proc_3)).unwrap();
        net.queue_packets(packets);
        net.drain_queued_packets();

        let mut msc_file = File::create("simple_join.msc").unwrap();
        msc_file.write_all(net.generate_msc().as_bytes()).unwrap();
    }

    #[derive(Debug, Clone)]
    enum Instruction {
        RequestJoin(usize, usize),
        RequestLeave(usize, usize),
        DeliverPacketFromSource(usize),
    }
    impl Arbitrary for Instruction {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let p: usize = usize::arbitrary(g) % 7;
            let q: usize = usize::arbitrary(g) % 7;

            match u8::arbitrary(g) % 3 {
                0 => Instruction::RequestJoin(p, q),
                1 => Instruction::RequestLeave(p, q),
                2 => Instruction::DeliverPacketFromSource(p),
                i => panic!("unexpected instruction index {}", i),
            }
        }

        fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
            let mut shrunk_ops = Vec::new();
            match self.clone() {
                Instruction::RequestJoin(p, q) => {
                    if p > 0 && q > 0 {
                        shrunk_ops.push(Instruction::RequestJoin(p - 1, q - 1));
                    }
                    if p > 0 {
                        shrunk_ops.push(Instruction::RequestJoin(p - 1, q));
                    }
                    if q > 0 {
                        shrunk_ops.push(Instruction::RequestJoin(p, q - 1));
                    }
                }
                Instruction::RequestLeave(p, q) => {
                    if p > 0 && q > 0 {
                        shrunk_ops.push(Instruction::RequestLeave(p - 1, q - 1));
                    }
                    if p > 0 {
                        shrunk_ops.push(Instruction::RequestLeave(p - 1, q));
                    }
                    if q > 0 {
                        shrunk_ops.push(Instruction::RequestLeave(p, q - 1));
                    }
                }
                Instruction::DeliverPacketFromSource(p) => {
                    if p > 0 {
                        shrunk_ops.push(Instruction::DeliverPacketFromSource(p - 1));
                    }
                }
            }

            Box::new(shrunk_ops.into_iter())
        }
    }

    quickcheck! {
        fn prop_interpreter(n: usize, instructions: Vec<Instruction>) -> TestResult {
            fn super_majority(m: usize, n: usize) -> bool {
                3 * m > 2 * n
            }
            let n = n.min(7);
            if n == 0 || instructions.len() > 12{
                return TestResult::discard();
            }

            println!("--------------------------------------");

            let mut net = Net::with_procs(n);

            // Assume procs[0] is the genesis proc. (trusts itself)
            let gen_proc = net.genesis();
            for proc in net.procs.iter_mut() {
                proc.trust(gen_proc);
            }


            for instruction in instructions {
                match instruction {
                    Instruction::RequestJoin(p_idx, q_idx) => {
                        // p requests to join q
                        let p = net.procs[p_idx.min(n - 1)].id.actor();
                        let reconfig = Reconfig::Join(p);

                        let q = &mut net.procs[q_idx.min(n - 1)];
                        match q.propose(reconfig.clone()) {
                            Ok(propose_packets) => {
                                net.reconfigs_by_gen.entry(q.pending_gen).or_default().insert(reconfig);
                                assert!(propose_packets.iter().all(|p| p.source == q.id.actor()));
                                net.queue_packets(propose_packets);
                            }
                            Err(Error::JoinRequestForExistingMember { .. }) => {
                                assert!(q.members(q.gen).unwrap().contains(&p));
                            }
                            Err(Error::VoteFromNonMember { .. }) => {
                                assert!(!q.members(q.gen).unwrap().contains(&q.id.actor()));
                            }
                            Err(Error::ExistingVoteIncompatibleWithNewVote { vote, existing_vote }) => {
                                // This proc has already committed to a vote this round
                                assert_ne!(vote, existing_vote);
                                assert_eq!(q.votes.get(&q.id.actor()), Some(&existing_vote));
                                assert_eq!(vote.ballot, Ballot::Propose(reconfig));
                            }
                            Err(err) => {
                                // invalid request.
                                panic!("Failure to reconfig is not handled yet: {:?}", err);
                            }
                        }
                    },
                    Instruction::RequestLeave(p_idx, q_idx) => {
                        // p requests to leave q
                        let p = net.procs[p_idx.min(n - 1)].id.actor();
                        let reconfig = Reconfig::Leave(p);

                        let q = &mut net.procs[q_idx.min(n - 1)];
                        match q.propose(reconfig.clone()) {
                            Ok(propose_packets) => {
                                net.reconfigs_by_gen.entry(q.pending_gen).or_default().insert(reconfig);
                                assert!(propose_packets.iter().all(|p| p.source == q.id.actor()));
                                net.queue_packets(propose_packets);
                            }
                            Err(Error::LeaveRequestForNonMember { .. }) => {
                                assert!(!q.members(q.gen).unwrap().contains(&p));
                            }
                            Err(Error::VoteFromNonMember { .. }) => {
                                assert!(!q.members(q.gen).unwrap().contains(&q.id.actor()));
                            }
                            Err(Error::ExistingVoteIncompatibleWithNewVote { vote, existing_vote }) => {
                                // This proc has already committed to a vote
                                assert_ne!(vote, existing_vote);
                                assert_eq!(q.votes.get(&q.id.actor()), Some(&existing_vote));
                                assert_eq!(vote.ballot, Ballot::Propose(reconfig));
                            }
                            Err(err) => {
                                // invalid request.
                                panic!("Leave Failure is not handled yet: {:?}", err);
                            }
                        }
                    },
                    Instruction::DeliverPacketFromSource(source_idx) => {
                        // deliver packet
                        let source = net.procs[source_idx.min(n - 1)].id.actor();
                        net.deliver_packet_from_source(source);
                    }
                }
            }

            println!("{:#?}", net);
            println!("--  [DRAINING]  --");
            net.drain_queued_packets();
            println!("{:#?}", net);

            // We should have no more pending votes.
            for p in net.procs.iter() {
                assert_eq!(p.votes, Default::default());
            }

            let mut procs_by_gen: BTreeMap<Generation, Vec<State>> = Default::default();

            for proc in net.procs {
                procs_by_gen.entry(proc.gen).or_default().push(proc);
            }

            let max_gen = procs_by_gen.keys().last().unwrap();

            // And procs at each generation should have agreement on members
            for (gen, procs) in procs_by_gen.iter() {
                let mut proc_iter = procs.iter();
                let first = proc_iter.next().unwrap();
                if *gen > 0 {
                    // TODO: remove this gen > 0 constraint
                    assert_eq!(first.members(first.gen).unwrap(), net.members_at_gen[&gen]);
                }
                for proc in proc_iter {
                    assert_eq!(first.members(first.gen).unwrap(), proc.members(proc.gen).unwrap(), "gen: {}", gen);
                }
            }

            // TODO: everyone that a proc at G considers a member is also at generation G

            for (gen, reconfigs) in net.reconfigs_by_gen.iter() {
                let members_at_prev_gen = net.members_at_gen[&(gen - 1)].clone();
                let members_at_curr_gen = net.members_at_gen[&gen].clone();
                let mut reconfigs_applied: BTreeSet<&Reconfig> = Default::default();
                for reconfig in reconfigs {
                    match reconfig {
                        Reconfig::Join(p) => {
                            assert!(!members_at_prev_gen.contains(&p));
                            if members_at_curr_gen.contains(&p) {
                                reconfigs_applied.insert(reconfig);
                            }
                        }
                        Reconfig::Leave(p) => {
                            assert!(members_at_prev_gen.contains(&p));
                            if !members_at_curr_gen.contains(&p) {
                                reconfigs_applied.insert(reconfig);
                            }
                        }
                    }
                }

                assert_ne!(reconfigs_applied, Default::default());
            }

            // The last gen should have at least a super majority of nodes
                    // The last gen should have at least a super majority of nodes
            // let current_members: BTreeSet<_> =
            //     procs_by_gen[max_gen].iter().map(|p| p.id.actor()).collect();

            // for proc in procs_by_gen[max_gen].iter() {
            //     assert_eq!(current_members, proc.members);
            // }

        let proc_at_max_gen = procs_by_gen[max_gen].iter().next().unwrap();
            assert!(super_majority(procs_by_gen[max_gen].len(), proc_at_max_gen.members(*max_gen).unwrap().len()), "{:?}", procs_by_gen);

            // assert_eq!(net.pending_reconfigs, Default::default());

            // ensure all procs are in the same generations
            // ensure all procs agree on the same members
            TestResult::passed()
        }

        fn prop_validate_reconfig(join_or_leave: bool, actor_idx: usize, members: u8) -> TestResult {
            if members + 1 > 7 {
                // + 1 from the initial proc
                return TestResult::discard();
            }

            let mut proc = State::default();

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
            let proc_members = proc.members(proc.gen).unwrap();
            match reconfig {
                Reconfig::Join(actor) => {
                    if proc_members.contains(&actor) {
                        assert!(matches!(valid_res, Err(Error::JoinRequestForExistingMember {..})));
                    } else if members + 1 == 7 {
                        assert!(matches!(valid_res, Err(Error::MembersAtCapacity {..})));
                    } else {
                        assert!(valid_res.is_ok());
                    }
                }
                Reconfig::Leave(actor) => {
                    if proc_members.contains(&actor) {
                        assert!(valid_res.is_ok());
                    } else {
                        assert!(matches!(valid_res, Err(Error::LeaveRequestForNonMember {..})));

                    }
                }
            };

            TestResult::passed()
        }
    }
}
