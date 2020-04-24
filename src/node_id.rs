//! The identifier for an ENR record. This is the keccak256 hash of the public key (for secp256k1
//! keys this is the uncompressed encoded form of the public key).

use crate::{Enr, EnrKey};
use ethereum_types::H256;

/// The `NodeId` of an ENR (a 32 byte identifier).
pub type NodeId = H256;

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
