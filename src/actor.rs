use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

use ed25519::{Keypair, PublicKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Eq, Clone, Copy, Serialize, Deserialize)]
pub struct Actor(pub PublicKey);

impl Actor {
    pub fn verify(&self, blob: impl Serialize, sig: &Sig) -> Result<bool, bincode::Error> {
        let blob_bytes = bincode::serialize(&blob)?;
        Ok(self.0.verify(&blob_bytes, &sig.0).is_ok())
    }
}

impl Default for Actor {
    fn default() -> Self {
        SigningActor::default().actor()
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
        self.0.as_bytes().cmp(&other.0.as_bytes())
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

pub struct SigningActor(pub Keypair);

impl Default for SigningActor {
    fn default() -> Self {
        Self(Keypair::generate(&mut OsRng))
    }
}

impl SigningActor {
    pub fn actor(&self) -> Actor {
        Actor(self.0.public)
    }

    pub fn sign(&self, blob: impl Serialize) -> Result<Sig, bincode::Error> {
        let blob_bytes = bincode::serialize(&blob)?;
        let blob_sig = self.0.sign(&blob_bytes);
        Ok(Sig(blob_sig))
    }
}

impl fmt::Display for SigningActor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.actor(), f)
    }
}

impl fmt::Debug for SigningActor {
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

impl PartialOrd for Sig {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.0.to_bytes().partial_cmp(&other.0.to_bytes())
    }
}

impl Ord for Sig {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.to_bytes().cmp(&other.0.to_bytes())
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
