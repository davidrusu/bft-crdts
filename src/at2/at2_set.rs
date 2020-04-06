use std::collections::{HashMap, HashSet};

pub type Identity = u8;
pub type Account = Identity; // In the paper, Identity and Account are synonymous
pub type Money = i64;
pub type Member = u8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SetOp {
    Add(Member),
    Rm(Member),
}

impl SetOp {
    /// TODO: generalize the term "account", borrowed here from asset trasfer (Does "resource" capture it?)
    /// These affected accounts become causally dependent on this operation.
    pub fn affected_accounts(&self) -> HashSet<Member> {
        match self {
            SetOp::Add(member) => vec![member].into_iter().collect(),
            SetOp::Rm(member) => vec![member].into_iter().collect(),
        }
    }
}

#[derive(Debug)]
pub struct Set {
    members: HashSet<Member>,
}

impl Set {
    pub fn new() -> Self {
        Set {
            members: HashSet::new(),
        }
    }

    pub fn members(&self) -> HashSet<Member> {
        self.members.clone()
    }

    pub fn add(&self, member: Member) -> SetOp {
        SetOp::Add(member)
    }

    pub fn rm(&self, member: Member) -> SetOp {
        SetOp::Rm(member)
    }

    /// Protection against Byzantines
    pub fn validate(&self, source_proc: Identity, op: &Transfer) -> bool {
        // The framework provided all the protection we needed :)
        true
    }

    /// Executed once an op has been validated
    pub fn apply(&mut self, op: Transfer) {
        match op {
            SetOP::Add(member) => self.members.insert(member),
            SetOp::Rm(member) => self.members.remove(member),
        }
    }
}
