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
    
    /// Producer digital signature of this block
    pub signature: Vec<u8>,
}

impl Block {
    /// Block default constructor
    pub fn new(
        block_header: BlockHeader,
        block_hash: [u8; 32],
        block_data: Vec<u8>,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            block_header,
            block_hash,
            block_data,
            signature,
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
    fn new_genesis<H: crate::traits::BlockHeaderHasher>(hasher: &H, block_data: Vec<u8>, signature: Vec<u8>) -> Self {
        let header = BlockHeader::new([0u8; 32]);
        let mut block = Block::new(
            header,
            [0u8; 32],
            block_data,
            signature,
        );
        let header_hash = block.header_hash(hasher);
        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&header_hash[..32.min(header_hash.len())]);
        block.block_hash = block_hash;
        block
    }
}

impl RegularBlock for Block {
    fn new_block<H: crate::traits::BlockHeaderHasher>(hasher: &H, parent_hash: [u8; 32], block_data: Vec<u8>, signature: Vec<u8>) -> Self {
        let header = BlockHeader::new(parent_hash);
        let mut block = Block::new(
            header,
            [0u8; 32],
            block_data,
            signature,
        );
        let header_hash = block.header_hash(hasher);
        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&header_hash[..32.min(header_hash.len())]);
        block.block_hash = block_hash;
        block
    }
}
