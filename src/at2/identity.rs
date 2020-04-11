use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

use ed25519_dalek::PublicKey;
use serde::Serialize;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize)]
pub struct Identity(pub PublicKey);

impl Hash for Identity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_bytes().hash(state);
    }
}

impl PartialOrd for Identity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.0.as_bytes().partial_cmp(&other.0.as_bytes())
    }
}

impl Ord for Identity {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(&other).unwrap()
    }
}
