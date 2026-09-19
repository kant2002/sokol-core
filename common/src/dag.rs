use core::error::Error;
use core::fmt;

pub const HASH_SIZE: usize = 32;
pub const IPV6_SIZE: usize = 16;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DagError {
    MissingParentPointer,
    InvalidGenesisAnchor,
    TopologicalCycleDetected,
    MalformedNodeStructure,
    UnspecifiedOriginIp,
}

impl fmt::Display for DagError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DagError::MissingParentPointer => {
                write!(f, "DAG Error: Event node lacks a valid prior parent hash")
            }
            DagError::InvalidGenesisAnchor => write!(f, "DAG Error: Genesis node anchor mismatch"),
            DagError::TopologicalCycleDetected => {
                write!(f, "DAG Error: Causal loop or topological order violation")
            }
            DagError::MalformedNodeStructure => {
                write!(f, "DAG Error: Node structure violates strict length constraints")
            }
            DagError::UnspecifiedOriginIp => {
                write!(f, "DAG Error: Origin IP address is unspecified (all zeros)")
            }
        }
    }
}

impl Error for DagError {}

pub struct TopologicalEventNode<'a> {
    pub event_id: [u8; HASH_SIZE],
    pub prior_hash: [u8; HASH_SIZE],
    pub origin_ip: [u8; IPV6_SIZE],
    pub payload: &'a [u8],
}

impl<'a> TopologicalEventNode<'a> {
    pub fn verify_causal_integrity(
        &self,
        genesis_anchor: &[u8; HASH_SIZE],
        known_history: &[[u8; HASH_SIZE]],
    ) -> Result<(), DagError> {
        if self.prior_hash == [0u8; HASH_SIZE] {
            return Err(DagError::MissingParentPointer);
        }

        if self.prior_hash == self.event_id {
            return Err(DagError::TopologicalCycleDetected);
        }

        if self.prior_hash != *genesis_anchor && !known_history.contains(&self.prior_hash) {
            return Err(DagError::InvalidGenesisAnchor);
        }

        if self.payload.is_empty() {
            return Err(DagError::MalformedNodeStructure);
        }

        if self.origin_ip == [0u8; IPV6_SIZE] {
            return Err(DagError::UnspecifiedOriginIp);
        }

        Ok(())
    }
}