//! The identifier for an ENR record. This is the keccak256 hash of the public key (for secp256k1
//! keys this is the uncompressed encoded form of the public key).

use crate::{digest, keys::EnrPublicKey, Enr, EnrKey};
use ethereum_types::H256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
/// The `NodeId` of an ENR (a 32 byte identifier).
pub struct NodeId(H256);

impl NodeId {
    /// Creates a new node record from 32 bytes.
    #[must_use]
    pub const fn new(raw_input: &[u8; 32]) -> Self {
        Self(H256(*raw_input))
    }

    /// Parses a byte slice to form a node Id. This fails if the slice isn't of length 32.
    pub fn parse(raw_input: &[u8]) -> Result<Self, &'static str> {
        if raw_input.len() > 32 {
            return Err("Input too large");
        }

        let mut raw = [0_u8; 32];
        raw[..std::cmp::min(32, raw_input.len())].copy_from_slice(raw_input);

        Ok(Self(H256(raw)))
    }

    /// Generates a random `NodeId`.
    #[must_use]
    pub fn random() -> Self {
        Self(rand::random())
    }

    /// Returns a `H256` which is a 32 byte list.
    #[must_use]
    pub const fn raw(&self) -> H256 {
        self.0
    }
}

impl<T: EnrPublicKey> From<T> for NodeId {
    fn from(public_key: T) -> Self {
        let pubkey_bytes = public_key.encode_uncompressed();
        Self::parse(&digest(&pubkey_bytes)).expect("always of correct length; qed")
    }
}

impl<T: EnrKey> From<Enr<T>> for NodeId {
    fn from(enr: Enr<T>) -> Self {
        enr.node_id()
    }
}

impl<T: EnrKey> From<&Enr<T>> for NodeId {
    fn from(enr: &Enr<T>) -> Self {
        enr.node_id()
    }
}

impl From<H256> for NodeId {
    fn from(value: H256) -> Self {
        Self(value)
    }
}

impl From<NodeId> for H256 {
    fn from(value: NodeId) -> Self {
        value.0
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let hex_encode = hex::encode(self.0);
        write!(
            f,
            "0x{}..{}",
            &hex_encode[0..4],
            &hex_encode[hex_encode.len() - 4..]
        )
    }
}
