//! Block structure for a blockchain implementation.
//!
//! Each block contains one block transaction and maintains the blockchain integrity
//! through cryptographic hashing and linking to previous blocks.

pub const BLOCK_VERSION: u32 = 1;
pub use libcertcrypto::CertificateTools;

/// Core header for a block in a blockchain.
/// This struct contains only cryptographically relevant data for hash calculations.
/// Block height is handled separately as database metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    /// Block Unique Identifier
    pub block_uid: uuid::Bytes,

    /// Header version to support upgrades.
    pub version: u32,

    /// Hash of the parent block (previous block).
    pub parent_hash: [u8; 32],

    /// Timestamp of block creation (UNIX epoch seconds).
    pub timestamp: u64,

    /// Nonce for proof-of-work or other consensus algorithms.
    pub nonce: u64,
}

impl BlockHeader {
    /// Create a fully constructed new header convenience constructor.
    /// Note: block_height is handled separately as database metadata.
    pub fn new(
        parent_hash: [u8; 32],
    ) -> (Self, [u8; 32]) {
        use std::time::{SystemTime, UNIX_EPOCH};
        use uuid::Uuid;
        use rand::Rng;
        
        let block_uid = Uuid::new_v4().as_bytes().to_owned();
        let version = BLOCK_VERSION;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        let nonce: u64 = rand::rng().random();
        let header = Self {
            block_uid,
            version,
            parent_hash,
            timestamp,
            nonce,
        };
        let block_hash = header.generate_block_hash();
        (header, block_hash)
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.block_uid);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.parent_hash);
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        bytes
    }

    pub fn generate_block_hash(&self) -> [u8; 32] {
        let header_bytes = self.get_bytes();
        let hash_vec = CertificateTools::hash_sha256(&header_bytes)
            .expect("SHA-256 hashing failed");
        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&hash_vec[..32]);
        block_hash
    }
}

/// Represents a block in the blockchain
#[derive(Debug, Clone)]
pub struct Block {
    /// Block Header (cryptographically relevant data only)
    pub block_header: BlockHeader,

    /// This block's cryptographic hash (serialized header + block_data)
    pub block_hash: [u8; 32],

    /// Application-specific block data (opaque to this library)
    pub block_data: Vec<u8>,
}

impl Block {
    /// Regular constructor for Block
    pub fn new_regular_block(
        parent_hash: [u8; 32],
        block_data: Vec<u8>,
    ) -> Self {
        let (header, block_hash) = BlockHeader::new(parent_hash);
        Self {
            block_header: header,
            block_hash: block_hash,
            block_data: block_data,
        }
    }
    /// Genesis block constructor
    pub fn new_genesis_block(
        block_data: Vec<u8>,
    ) -> Self {
        let (header, block_hash) = BlockHeader::new([0u8; 32]);
        Self {
            block_header: header,
            block_hash: block_hash,
            block_data: block_data,

        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_header_creation() {
        let parent_hash = [1u8; 32];
        let (header, block_hash) = BlockHeader::new(parent_hash);
        
        assert_eq!(header.version, BLOCK_VERSION);
        assert_eq!(header.parent_hash, parent_hash);
        assert!(header.timestamp > 0);
        assert_eq!(header.block_uid.len(), 16); // UUID is 16 bytes
        assert_ne!(block_hash, [0u8; 32]); // Hash should be generated
    }

    #[test]
    fn test_genesis_block_has_zero_parent_hash() {
        let block_data = vec![1, 2, 3, 4];
        let genesis = Block::new_genesis_block(block_data.clone());
        
        assert_eq!(genesis.block_header.parent_hash, [0u8; 32]);
        assert_eq!(genesis.block_data, block_data);
        assert_ne!(genesis.block_hash, [0u8; 32]); // Hash should be computed
    }

    #[test]
    fn test_regular_block_creation() {
        let parent_hash = [5u8; 32];
        let block_data = vec![10, 20, 30];
        
        let block = Block::new_regular_block(parent_hash, block_data.clone());
        
        assert_eq!(block.block_header.parent_hash, parent_hash);
        assert_eq!(block.block_data, block_data);
        assert_ne!(block.block_hash, [0u8; 32]);
    }

    #[test]
    fn test_header_bytes_serialization() {
        let (header, _) = BlockHeader::new([42u8; 32]);
        
        let bytes = header.get_bytes();
        
        // Should contain: uid(16) + version(4) + parent_hash(32) + timestamp(8) + nonce(8) = 68 bytes
        assert_eq!(bytes.len(), 68);
        
        // Verify parent_hash is in the serialized bytes
        assert!(bytes.windows(32).any(|window| window == &[42u8; 32]));
    }

    #[test]
    fn test_block_hash_computation() {
        let block_data = vec![100, 101, 102];
        let block = Block::new_genesis_block(block_data);
        
        // Recompute hash to verify it matches
        let computed_hash = block.block_header.generate_block_hash();
        
        assert_eq!(block.block_hash, computed_hash);
    }

    #[test]
    fn test_different_blocks_have_different_uids() {
        let (header1, _) = BlockHeader::new([0u8; 32]);
        let (header2, _) = BlockHeader::new([0u8; 32]);
        
        assert_ne!(header1.block_uid, header2.block_uid);
    }

    #[test]
    fn test_block_chain_linking() {
        // Create genesis block
        let genesis = Block::new_genesis_block(vec![1, 2, 3]);
        
        // Create next block using genesis hash
        let block2 = Block::new_regular_block(genesis.block_hash, vec![4, 5, 6]);
        
        assert_eq!(block2.block_header.parent_hash, genesis.block_hash);
        
        // Create third block
        let block3 = Block::new_regular_block(block2.block_hash, vec![7, 8, 9]);
        
        assert_eq!(block3.block_header.parent_hash, block2.block_hash);
    }
}
