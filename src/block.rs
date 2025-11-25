//! Block structure for a blockchain implementation.
//!
//! Each block contains one block transaction and maintains the blockchain integrity
//! through cryptographic hashing and linking to previous blocks.

use crate::traits::{GenesisBlock, RegularBlock};

pub const BLOCK_VERSION: u32 = 1;

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

    /// Unix timestamp (seconds since epoch).
    pub timestamp: u64,

    /// Nonce radomized for entropy.
    pub nonce: u64,
}

impl BlockHeader {
    /// Create a minimal new header convenience constructor.
    /// Note: block_height is handled separately as database metadata.
    pub fn new(
        parent_hash: [u8; 32],
    ) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        use uuid::Uuid;
        use rand::Rng;
        
        Self {
            block_uid: *Uuid::new_v4().as_bytes(),
            version: BLOCK_VERSION,
            parent_hash,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs(),
            nonce: rand::rng().random::<u64>(),
        }
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
    /// Block default constructor
    pub fn new(
        block_header: BlockHeader,
        block_hash: [u8; 32],
        block_data: Vec<u8>,
    ) -> Self {
        Self {
            block_header,
            block_hash,
            block_data,
        }
    }
    
    pub fn header_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.block_header.block_uid);
        bytes.extend_from_slice(&self.block_header.version.to_le_bytes());
        bytes.extend_from_slice(&self.block_header.parent_hash);
        bytes.extend_from_slice(&self.block_header.timestamp.to_le_bytes());
        bytes.extend_from_slice(&self.block_header.nonce.to_le_bytes());
        bytes
    }
    
    pub fn header_hash<H: crate::traits::BlockHeaderHasher>(&self, hasher: &H) -> Vec<u8> {
        hasher.hash(&self.header_bytes())
    }
}

impl GenesisBlock for Block {
    fn new_genesis<H: crate::traits::BlockHeaderHasher>(hasher: &H, block_data: Vec<u8>) -> Self {
        let header = BlockHeader::new([0u8; 32]);
        let mut block = Block::new(
            header,
            [0u8; 32],
            block_data,
        );
        let header_hash = block.header_hash(hasher);
        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&header_hash[..32.min(header_hash.len())]);
        block.block_hash = block_hash;
        block
    }
}

impl RegularBlock for Block {
    fn new_block<H: crate::traits::BlockHeaderHasher>(hasher: &H, parent_hash: [u8; 32], block_data: Vec<u8>) -> Self {
        let header = BlockHeader::new(parent_hash);
        let mut block = Block::new(
            header,
            [0u8; 32],
            block_data,
        );
        let header_hash = block.header_hash(hasher);
        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&header_hash[..32.min(header_hash.len())]);
        block.block_hash = block_hash;
        block
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::BlockHeaderHasher;

    // Simple test hasher for testing
    struct TestHasher;
    
    impl BlockHeaderHasher for TestHasher {
        fn hash(&self, data: &[u8]) -> Vec<u8> {
            // Simple hash: just return first 32 bytes or pad with zeros
            let mut result = vec![0u8; 32];
            let len = data.len().min(32);
            result[..len].copy_from_slice(&data[..len]);
            result
        }
        
        fn hash_size(&self) -> usize {
            32
        }
    }

    #[test]
    fn test_block_header_creation() {
        let parent_hash = [1u8; 32];
        let header = BlockHeader::new(parent_hash);
        
        assert_eq!(header.version, BLOCK_VERSION);
        assert_eq!(header.parent_hash, parent_hash);
        assert!(header.timestamp > 0);
        assert_eq!(header.block_uid.len(), 16); // UUID is 16 bytes
    }

    #[test]
    fn test_genesis_block_has_zero_parent_hash() {
        let hasher = TestHasher;
        let block_data = vec![1, 2, 3, 4];
        let genesis = Block::new_genesis(&hasher, block_data.clone());
        
        assert_eq!(genesis.block_header.parent_hash, [0u8; 32]);
        assert_eq!(genesis.block_data, block_data);
        assert_ne!(genesis.block_hash, [0u8; 32]); // Hash should be computed
    }

    #[test]
    fn test_regular_block_creation() {
        let hasher = TestHasher;
        let parent_hash = [5u8; 32];
        let block_data = vec![10, 20, 30];
        
        let block = Block::new_block(&hasher, parent_hash, block_data.clone());
        
        assert_eq!(block.block_header.parent_hash, parent_hash);
        assert_eq!(block.block_data, block_data);
        assert_ne!(block.block_hash, [0u8; 32]);
    }

    #[test]
    fn test_header_bytes_serialization() {
        let header = BlockHeader::new([42u8; 32]);
        let block = Block::new(header.clone(), [0u8; 32], vec![]);
        
        let bytes = block.header_bytes();
        
        // Should contain: uid(16) + version(4) + parent_hash(32) + timestamp(8) + nonce(8) = 68 bytes
        assert_eq!(bytes.len(), 68);
        
        // Verify parent_hash is in the serialized bytes
        assert!(bytes.windows(32).any(|window| window == &[42u8; 32]));
    }

    #[test]
    fn test_block_hash_computation() {
        let hasher = TestHasher;
        let block_data = vec![100, 101, 102];
        let block = Block::new_genesis(&hasher, block_data);
        
        let computed_hash = block.header_hash(&hasher);
        
        assert_eq!(computed_hash.len(), 32);
        assert_eq!(block.block_hash[..], computed_hash[..32]);
    }

    #[test]
    fn test_different_blocks_have_different_uids() {
        let header1 = BlockHeader::new([0u8; 32]);
        let header2 = BlockHeader::new([0u8; 32]);
        
        assert_ne!(header1.block_uid, header2.block_uid);
    }

    #[test]
    fn test_block_chain_linking() {
        let hasher = TestHasher;
        
        // Create genesis block
        let genesis = Block::new_genesis(&hasher, vec![1, 2, 3]);
        
        // Create next block using genesis hash
        let block2 = Block::new_block(&hasher, genesis.block_hash, vec![4, 5, 6]);
        
        assert_eq!(block2.block_header.parent_hash, genesis.block_hash);
        
        // Create third block
        let block3 = Block::new_block(&hasher, block2.block_hash, vec![7, 8, 9]);
        
        assert_eq!(block3.block_header.parent_hash, block2.block_hash);
    }
}
