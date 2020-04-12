use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

use ed25519_dalek::{PublicKey, Signature};
use hex;
use serde::Serialize;

#[derive(PartialEq, Eq, Clone, Copy, Serialize)]
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

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.0.as_bytes();
        let visible = 1;
        write!(
            f,
            "ID:{}..{}",
            hex::encode(&bytes[..visible]),
            hex::encode(&bytes[bytes.len() - visible..bytes.len()])
        )
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Serialize)]
pub struct Sig(pub Signature);

impl Hash for Sig {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bytes().hash(state);
    }
}

impl fmt::Display for Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.0.to_bytes();
        let visible = 1;
        write!(
            f,
            "Sig:{}..{}",
            hex::encode(&bytes[..visible]),
            hex::encode(&bytes[bytes.len() - visible..bytes.len()])
        )
    }
}

impl fmt::Debug for Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}
