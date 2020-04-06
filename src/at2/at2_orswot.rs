use std::collections::{HashMap, HashSet};

use crdts::orswot::{Op, Orswot};

pub type Identity = u8;
pub type Account = Identity; // In the paper, Identity and Account are synonymous
pub type Member = u8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AT2Op(Op<Member, Identity>);

impl AT2Op {
    /// TODO: generalize the term "account", borrowed here from asset trasfer (Does "resource" capture it?)
    /// These affected accounts become causally dependent on this operation.
    pub fn affected_accounts(&self, source: Identity) -> HashSet<Account> {
        vec![source].into_iter().collect()
    }
}

#[derive(Debug, Default)]
pub struct AT2Orswot {
    orswot: Orswot<Member, Identity>,
    // Set of all Add op's that have been accepted and applied.
    // This is used to validate orswot::Op::Rm operations since
    // we need to ensure that a member was added by a source before
    // we can remove that member
    history: HashMap<Dot, Member>,
}

impl AT2Orswot {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn members(&self) -> HashSet<Member> {
        self.orswot.read().val
    }

    pub fn contains(&self, member: &Member) -> bool {
        self.contains(member).val
    }

    pub fn add(&self, identity: Identity, member: &Member) -> Option<AT2Op> {
        let read_ctx = self.orswot.contains(&member);
        if read_ctx.val {
            Some(self.orswot.add(member, read_ctx.derive_add_ctx(identity)))
        } else {
            None
        }
    }

    pub fn rm(&self, member: &Member) -> AT2Op {
        let read_ctx = self.orswot.contains(&member);
        if read_ctx.val {
            Some(self.orswot.rm(member, read_ctx.derive_rm_ctx()))
        } else {
            None
        }
    }

    /// Protection against Byzantines
    pub fn validate(&self, source_dot: Dot, op: &AT2Op) -> bool {
        match op {
            AT2Op(Op::Add { dot, members }) => {
                if source_dot != dot {
                    println!("[INVALID] add dot does not match the source dot");
                    false
                } else {
                    true
                }
            }
            AT2Op(Op::Rm { clock, members }) => {
                assert_eq!(members.len(), 1); // we currently only support removing one member at a time
                let member = members[0];
                if clock
                    .iter()
                    .any(|dot| self.history.get(dot) != Some(member))
                {
                    println!("[INVALID] not all witnessing dots have added this member");
                    false
                } else {
                    true
                }
            }
        }
    }

    /// Executed once an op has been validated
    pub fn apply(&mut self, op: Transfer) {
        let unwrapped_op = op.0;
        if let Op::Add { dot, member } = unwrapped_op {
            // Store the witnessing dot with the member so that we
            // can validate any future removals of a member.
            self.history.insert(dot, member);
        }

        self.orswot.apply(op)
    }
}
