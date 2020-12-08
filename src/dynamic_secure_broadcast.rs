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
    history: BTreeMap<Generation, Vote>, // for onboarding new procs, the vote proving quorum
    votes: BTreeMap<Actor, Vote>,
    faulty: bool,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
enum Reconfig {
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

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
enum Ballot {
    Propose(Reconfig),
    Merge(BTreeSet<Vote>),
    Quorum(BTreeSet<Vote>),
}

impl std::fmt::Debug for Ballot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ballot::Propose(r) => write!(f, "P({:?})", r),
            Ballot::Merge(votes) => write!(f, "M{:?}", votes),
            Ballot::Quorum(votes) => write!(f, "Q{:?}", votes),
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct Vote {
    gen: Generation,
    ballot: Ballot,
    voter: Actor,
    sig: Sig,
}

impl std::fmt::Debug for Vote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "V(G{},{:?},{:?})", self.gen, self.ballot, self.voter)
    }
}

impl Vote {
    fn is_quorum(&self) -> bool {
        match self.ballot {
            Ballot::Quorum(_) => true,
            _ => false,
        }
    }

    fn reconfigs(&self) -> BTreeSet<(Actor, Reconfig)> {
        match &self.ballot {
            Ballot::Propose(reconfig) => vec![(self.voter, reconfig.clone())].into_iter().collect(),
            Ballot::Merge(votes) | Ballot::Quorum(votes) => {
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
                Ballot::Merge(votes) | Ballot::Quorum(votes) => {
                    votes.iter().any(|v| v.supersedes(vote))
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
    ExistingVoteFromVoterIsNotPresentInNewVote {
        vote: Vote,
        existing_vote: Vote,
    },
    QuorumBallotIsNotQuorum {
        ballot: Ballot,
        members: BTreeSet<Actor>,
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
        self.log_vote(&vote);
        Ok(self.broadcast(vote))
    }

    pub fn handle_packet(&mut self, packet: Packet) -> Result<Vec<Packet>, Error> {
        self.validate_packet(&packet)?;
        let Packet { vote, .. } = packet;

        self.log_vote(&vote);

        if self.gen == self.pending_gen && self.pending_gen + 1 == vote.gen {
            println!("[DSB] gen change {:?}->{:?}", self.gen, vote.gen);
            self.pending_gen = vote.gen;
        }

        assert_eq!(self.gen + 1, self.pending_gen);

        if self.is_split_vote(&self.votes.values().cloned().collect()) {
            println!("[DSB] Detected split vote");
            if let Some(our_vote) = self.votes.get(&self.id.actor()) {
                if our_vote.ballot == vote.ballot {
                    println!("[DSB] we voted the same, waiting for more votes...");
                    return Ok(vec![]);
                } else if vote.supersedes(our_vote) {
                    println!("[DSB] their vote supercedes ours, adopting.");
                    return self.adopt_ballot(self.pending_gen, vote.ballot.clone());
                } else {
                    println!("[DSB] Our votes don't fully overlap, merge them.");
                    return self.adopt_ballot(
                        self.pending_gen,
                        Ballot::Merge(self.votes.values().cloned().collect()),
                    );
                }
            } else {
                println!("[DSB] We have not voted yet, merging split vote");
                return self.adopt_ballot(
                    self.pending_gen,
                    Ballot::Merge(self.votes.values().cloned().collect()),
                );
            }
        }

        if self.is_quorum_over_quorums(&self.votes.values().cloned().collect()) {
            println!("[DSB] Detected quorum over quorum");
            let agreed_upon_reconfigs = self.resolve_votes(&self.votes.values().cloned().collect());
            for reconfig in agreed_upon_reconfigs.iter().cloned() {
                self.apply(reconfig);
            }
            self.gen = self.pending_gen;

            // log a proof of what the network decided on so that we can onboard future procs.
            let ballot = Ballot::Quorum(self.votes.values().cloned().collect());
            let gen = self.pending_gen;
            let sig = self.id.sign((&ballot, &gen));
            let voter = self.id.actor();
            let vote = Vote {
                ballot,
                gen,
                voter,
                sig,
            };
            self.history.insert(self.gen, vote.clone());

            // figure out which procs we need to onboard
            let new_procs: BTreeSet<Actor> = agreed_upon_reconfigs
                .into_iter()
                .filter_map(|r| match r {
                    Reconfig::Join(p) => Some(p),
                    Reconfig::Leave(_) => None,
                })
                .collect();

            // clear our pending votes
            self.votes = Default::default();

            let onboarding_packets = new_procs
                .into_iter()
                .flat_map(|p| {
                    // deliver the history in order from gen=1 onwards
                    self.history
                        .iter()
                        .map(|(_gen, membership_proof)| self.send(membership_proof.clone(), p))
                        .collect::<Vec<_>>()
                })
                .collect();

            return Ok(onboarding_packets);
        }

        if self.is_quorum(&self.votes.values().cloned().collect()) {
            println!("[DSB] Detected quorum");
            if let Some(our_vote) = self.votes.get(&self.id.actor()) {
                // did we already vote with a quorum?

                // We may have committed to some reconfigs that is not part of quorum.
                // This happens when the network was able to form quorum without our involvement.
                // We can not change our vote because right now all we know is that a subset of
                // the network saw quorum. It could still be the case that two subsets of the network
                // see different quorums, this case is resolved by the split vote detection.
                let vote_reconfigs: BTreeSet<_> =
                    vote.reconfigs().into_iter().map(|(_, r)| r).collect();
                let reconfigs_we_have_comitted_to_not_in_quorum = our_vote
                    .reconfigs()
                    .into_iter()
                    .filter(|(_, r)| !vote_reconfigs.contains(r))
                    .count();

                if reconfigs_we_have_comitted_to_not_in_quorum > 0 {
                    println!("[DSB] We have committed to reconfigs that the quorum has not seen, wait for split or Q/Q");
                    return Ok(vec![]);
                } else if our_vote.is_quorum() {
                    println!("[DSB] We've already sent a quorum, wait till we either split or Q/Q");
                    return Ok(vec![]);
                } else if vote.is_quorum() && vote.supersedes(&our_vote) {
                    println!("[DSB] Adopting their quorum");
                    return self.adopt_ballot(self.pending_gen, vote.ballot.clone());
                } else if vote.ballot != our_vote.ballot && vote.supersedes(our_vote) {
                    // This case is not expected to happen
                    panic!("[DSB] their vote supercedes our vote!!");
                } else {
                    println!("[DSB] broadcasting quorum");
                    return self.adopt_ballot(
                        self.pending_gen,
                        Ballot::Quorum(self.votes.values().cloned().collect()),
                    );
                }
            } else if vote.is_quorum() {
                println!("[DSB] Adopting their quorum");
                return self.adopt_ballot(self.pending_gen, vote.ballot.clone());
            } else {
                println!("[DSB] broadcasting quorum");
                return self.adopt_ballot(
                    self.pending_gen,
                    Ballot::Quorum(self.votes.values().cloned().collect()),
                );
            }
        }

        // We have determined that we don't yet have enough votes to take action.
        // If we have not yet voted, this is where we would contribute our vote
        if !self.votes.contains_key(&self.id.actor()) {
            // vote with all pending reconfigs
            return self.adopt_ballot(self.pending_gen, vote.ballot.clone());
        }

        Ok(vec![])
    }

    fn apply(&mut self, reconfig: Reconfig) {
        match reconfig {
            Reconfig::Join(peer) => self.members.insert(peer),
            Reconfig::Leave(peer) => self.members.remove(&peer),
        };
    }

    fn log_vote(&mut self, vote: &Vote) {
        let existing_vote = self.votes.entry(vote.voter).or_insert_with(|| vote.clone());
        if vote.supersedes(&existing_vote) {
            *existing_vote = vote.clone()
        }

        match &vote.ballot {
            Ballot::Propose(_) => (),
            Ballot::Quorum(votes) | Ballot::Merge(votes) => {
                for vote in votes.iter() {
                    self.log_vote(vote);
                }
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

    fn is_split_vote(&self, votes: &BTreeSet<Vote>) -> bool {
        let counts = self.count_votes(votes);
        let total_votes: usize = counts.values().sum();
        let most_votes = counts.values().max().cloned().unwrap_or_default();
        let n = self.members.len();
        let outstanding_votes = n - total_votes;
        let predicted_votes = most_votes + outstanding_votes;

        3 * total_votes > 2 * n && 3 * predicted_votes <= 2 * n
    }

    fn is_quorum(&self, votes: &BTreeSet<Vote>) -> bool {
        // TODO: quorum should always just be the largest 7 members
        let most_votes = self
            .count_votes(votes)
            .values()
            .max()
            .cloned()
            .unwrap_or_default();
        let n = self.members.len();

        3 * most_votes > 2 * n
    }

    fn is_quorum_over_quorums(&self, votes: &BTreeSet<Vote>) -> bool {
        let winning_reconfigs = self.resolve_votes(votes);

        let count_of_quorums = votes
            .iter()
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

    fn resolve_votes(&self, votes: &BTreeSet<Vote>) -> BTreeSet<Reconfig> {
        let (winning_reconfigs, _) = self
            .count_votes(votes)
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
        } else if vote.gen <= self.gen
            || (self.pending_gen > self.gen && vote.gen > self.pending_gen)
        {
            Err(Error::VoteNotForThisGeneration {
                vote_gen: vote.gen,
                gen: self.gen,
                pending_gen: self.pending_gen,
            })
        } else if !self.members.contains(&vote.voter) {
            Err(Error::VoteFromNonMember {
                voter: vote.voter,
                members: self.members.clone(),
            })
        } else if self.votes.contains_key(&vote.voter)
            && !vote.supersedes(&self.votes[&vote.voter])
            && !self.votes[&vote.voter].supersedes(&vote)
        {
            Err(Error::ExistingVoteFromVoterIsNotPresentInNewVote {
                vote: vote.clone(),
                existing_vote: self.votes[&vote.voter].clone(),
            })
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
        } else {
            panic!("Unhandled case {:?} {:#?}", vote, self);
        }
    }

    fn validate_ballot(&self, gen: Generation, ballot: &Ballot) -> Result<(), Error> {
        match ballot {
            Ballot::Propose(reconfig) => self.validate_reconfig(&reconfig),
            Ballot::Merge(votes) => {
                for vote in votes.iter() {
                    if vote.gen != gen {
                        return Err(Error::VoteNotForThisGeneration {
                            vote_gen: vote.gen,
                            gen: gen,
                            pending_gen: gen,
                        });
                    }
                    self.validate_vote(vote)?;
                }
                Ok(())
            }
            Ballot::Quorum(votes) => {
                if !self.is_quorum(votes) {
                    Err(Error::QuorumBallotIsNotQuorum {
                        ballot: ballot.clone(),
                        members: self.members.clone(),
                    })
                } else {
                    for vote in votes.iter() {
                        if vote.gen != gen {
                            return Err(Error::VoteNotForThisGeneration {
                                vote_gen: vote.gen,
                                gen: gen,
                                pending_gen: gen,
                            });
                        }
                        self.validate_vote(vote)?;
                    }
                    Ok(())
                }
                Ballot::Quorum(votes) => {
                    if !self.is_quorum(votes) {
                        Err(Error::QuorumBallotIsNotQuorum {
                            ballot: ballot.clone(),
                            members: self.members.clone(),
                        })
                    } else {
                        for vote in votes.iter() {
                            if vote.gen != gen {
                                return Err(Error::VoteNotForThisGeneration {
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
                .map(|member| self.send(vote.clone(), member))
                .collect()
        }

        fn send(&self, vote: Vote, dest: Actor) -> Packet {
            let source = self.id.actor();
            Packet { vote, source, dest }
        }
    }

    #[test]
    fn test_reject_changing_reconfig_when_one_is_in_progress() {
        let mut proc = Proc::default();
        proc.trust(proc.id.actor());
        assert!(proc.reconfig(Reconfig::Join(Actor::default())).is_ok());
        assert!(matches!(
            proc.reconfig(Reconfig::Join(Actor::default())),
            Err(Error::ExistingVoteFromVoterIsNotPresentInNewVote { .. })
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
                let packets = net.procs[i].reconfig(Reconfig::Join(member)).unwrap();
                net.queue_packets(packets);
            }

            net.drain_queued_packets();

            let expected_members = net.procs[0].members.clone();
            assert!(expected_members.len() > nprocs);

            for i in 0..nprocs {
                assert_eq!(net.procs[i].members, expected_members);
            }

            for member in expected_members.iter() {
                let p = net.procs.iter().find(|p| &p.id.actor() == member).unwrap();
                assert_eq!(p.members, expected_members);
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
        let packets = net.procs[0].reconfig(Reconfig::Join(p1)).unwrap();
        net.queue_packets(packets);
        net.deliver_packet_from_source(net.genesis());
        net.deliver_packet_from_source(net.genesis());
        let packets = net.procs[0].reconfig(Reconfig::Join(p2)).unwrap();
        net.queue_packets(packets);
        net.drain_queued_packets();

        let mut procs_by_gen: BTreeMap<Generation, Vec<Proc>> = Default::default();

        for proc in net.procs {
            procs_by_gen.entry(proc.gen).or_default().push(proc);
        }

        let max_gen = procs_by_gen.keys().last().unwrap();
        // The last gen should have at least a quorum of nodes
        let current_members: BTreeSet<_> =
            procs_by_gen[max_gen].iter().map(|p| p.id.actor()).collect();

        for proc in procs_by_gen[max_gen].iter() {
            assert_eq!(current_members, proc.members);
        }
    }

    #[derive(Default, Debug)]
    struct Net {
        procs: Vec<Proc>,
        reconfigs_by_gen: BTreeMap<Generation, BTreeSet<Reconfig>>,
        members_at_gen: BTreeMap<Generation, BTreeSet<Actor>>,
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

            let dest = packet.dest;

            assert_eq!(packet.source, source);

            println!(
                "delivering {:?}->{:?} {:#?}",
                packet.source, packet.dest, packet
            );

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

            let dest_members = dest_proc.members.clone();
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
                    assert_eq!(voter, source, "{:?} not in {:?}", voter, members);
                    assert_eq!(members, dest_members.clone());
                    assert!(!dest_members.contains(&source));
                }
                Err(Error::VoteNotForThisGeneration {
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
                let (mut proc_members, gen) = (proc.members.clone(), proc.gen);

                let expected_members_at_gen = self
                    .members_at_gen
                    .entry(gen)
                    .or_insert(proc_members.clone());

                assert_eq!(expected_members_at_gen, &mut proc_members);
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
            }
        }
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
            fn quorum(m: usize, n: usize) -> bool {
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
                        match q.reconfig(reconfig.clone()) {
                            Ok(reconfig_packets) => {
                                net.reconfigs_by_gen.entry(q.pending_gen).or_default().insert(reconfig);
                                assert!(reconfig_packets.iter().all(|p| p.source == q.id.actor()));
                                net.queue_packets(reconfig_packets);
                            }
                            Err(Error::JoinRequestForExistingMember { .. }) => {
                                assert!(q.members.contains(&p));
                            }
                            Err(Error::VoteFromNonMember { .. }) => {
                                assert!(!q.members.contains(&q.id.actor()));
                            }
                            Err(Error::ExistingVoteFromVoterIsNotPresentInNewVote { vote, existing_vote }) => {
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
                        match q.reconfig(reconfig.clone()) {
                            Ok(reconfig_packets) => {
                                net.reconfigs_by_gen.entry(q.pending_gen).or_default().insert(reconfig);
                                assert!(reconfig_packets.iter().all(|p| p.source == q.id.actor()));
                                net.queue_packets(reconfig_packets);
                            }
                            Err(Error::LeaveRequestForNonMember { .. }) => {
                                assert!(!q.members.contains(&p));
                            }
                            Err(Error::VoteFromNonMember { .. }) => {
                                assert!(!q.members.contains(&q.id.actor()));
                            }
                            Err(Error::ExistingVoteFromVoterIsNotPresentInNewVote { vote, existing_vote }) => {
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

            let mut procs_by_gen: BTreeMap<Generation, Vec<Proc>> = Default::default();

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
                    assert_eq!(first.members, net.members_at_gen[&gen]);
                }
                for proc in proc_iter {
                    assert_eq!(first.members, proc.members, "gen: {}", gen);
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

            // The last gen should have at least a quorum of nodes
                    // The last gen should have at least a quorum of nodes
            // let current_members: BTreeSet<_> =
            //     procs_by_gen[max_gen].iter().map(|p| p.id.actor()).collect();

            // for proc in procs_by_gen[max_gen].iter() {
            //     assert_eq!(current_members, proc.members);
            // }

            assert!(quorum(procs_by_gen[max_gen].len(), procs_by_gen[max_gen].iter().next().unwrap().members.len()), "{:?}", procs_by_gen);

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
