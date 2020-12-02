use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

use ed25519::{Keypair, PublicKey, Signature};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Eq, Clone, Copy, Serialize, Deserialize)]
pub struct Actor(pub PublicKey);

impl Actor {
    pub fn generate() -> (Self, Keypair) {
        let kp = Keypair::generate(&mut OsRng);
        let actor = Self(kp.public);
        (actor, kp)
    }
}

impl PartialEq for Actor {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Hash for Actor {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_bytes().hash(state);
    }
}

impl PartialOrd for Actor {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.0.as_bytes().partial_cmp(&other.0.as_bytes())
    }
}

impl Ord for Actor {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(&other).unwrap()
    }
}

impl fmt::Display for Actor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.0.as_bytes();
        write!(f, "i:{}", hex::encode(&bytes[..2]))
    }
}

impl fmt::Debug for Actor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

#[derive(Eq, Clone, Copy, Serialize, Deserialize)]
pub struct Sig(pub Signature);

impl PartialEq for Sig {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Hash for Sig {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bytes().hash(state);
    }
}

impl fmt::Display for Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.0.to_bytes();
        write!(f, "sig:{}", hex::encode(&bytes[..2]))
    }
}

impl fmt::Debug for Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}
