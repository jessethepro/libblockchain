//! Block structure for a blockchain implementation.
//!
//! Each block contains one block transaction and maintains the blockchain integrity
//! through cryptographic hashing and linking to previous blocks.

pub const BLOCK_VERSION: u32 = 1;
pub const BLOCK_UID_SIZE: usize = 16; // UUID size in bytes
pub const BLOCK_VERSION_SIZE: usize = 4; // u32 size in bytes
pub const BLOCK_HASH_SIZE: usize = 64; // SHA-512 hash size in bytes
pub const BLOCK_NONCE_SIZE: usize = 8; // u64 size in bytes
pub const BLOCK_TIMESTAMP_SIZE: usize = 8; // u64 size in bytes
pub const BLOCK_HEADER_SIZE: usize = 16 + 4 + 64 + 8 + 8; // uid + version + parent_hash + timestamp + nonce
use anyhow::{Result, anyhow};
use openssl::hash::MessageDigest;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    /// Block Unique Identifier
    pub block_uid: [u8; 16],

    /// Header version to support upgrades.
    pub version: u32,

    /// Hash of the parent block (previous block).
    pub parent_hash: [u8; 64],

    /// Timestamp of block creation (UNIX epoch seconds).
    pub timestamp: u64,

    /// Nonce for proof-of-work or other consensus algorithms.
    pub nonce: u64,
}

impl BlockHeader {
    /// Create a fully constructed new header
    /// Note: block_height is handled separately as database metadata.
    pub fn new(parent_hash: [u8; BLOCK_HASH_SIZE]) -> (Self, [u8; BLOCK_HASH_SIZE]) {
        use rand::Rng;
        use std::time::{SystemTime, UNIX_EPOCH};
        use uuid::Uuid;

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
        let block_hash = (|| {
            let hash_vec = openssl::hash::hash(MessageDigest::sha512(), &header.bytes())
                .expect("SHA-512 hashing failed")
                .to_vec();
            let mut hash = [0u8; BLOCK_HASH_SIZE];
            hash.copy_from_slice(&hash_vec[..BLOCK_HASH_SIZE]);
            hash
        })();
        (header, block_hash)
    }

    pub fn new_from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != 100 {
            return Err(anyhow!(
                "Invalid data length for BlockHeader: expected 100, got {}",
                data.len()
            ));
        }
        let mut index = 0;

        let block_uid = {
            let mut uid = [0u8; BLOCK_UID_SIZE];
            uid.copy_from_slice(&data[index..index + BLOCK_UID_SIZE]);
            index += BLOCK_UID_SIZE;
            uid
        };
        let version =
            u32::from_le_bytes(data[index..index + BLOCK_VERSION_SIZE].try_into().unwrap());
        index += BLOCK_VERSION_SIZE;
        let parent_hash = {
            let mut phash = [0u8; BLOCK_HASH_SIZE];
            phash.copy_from_slice(&data[index..index + BLOCK_HASH_SIZE]);
            index += BLOCK_HASH_SIZE;
            phash
        };
        let timestamp = u64::from_le_bytes(
            data[index..index + BLOCK_TIMESTAMP_SIZE]
                .try_into()
                .unwrap(),
        );
        index += BLOCK_TIMESTAMP_SIZE;
        let nonce = u64::from_le_bytes(data[index..index + BLOCK_NONCE_SIZE].try_into().unwrap());

        Ok(BlockHeader {
            block_uid,
            version,
            parent_hash,
            timestamp,
            nonce,
        })
    }

    pub fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.block_uid);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.parent_hash);
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        bytes
    }

    pub fn generate_block_hash(&self) -> [u8; 64] {
        let hash_vec = openssl::hash::hash(MessageDigest::sha512(), &self.bytes())
            .expect("SHA-512 hashing failed")
            .to_vec();
        let mut hash = [0u8; 64];
        hash.copy_from_slice(&hash_vec[..64]);
        hash
    }
}

/// Represents a block in the blockchain
#[derive(Debug, Clone)]
pub struct Block {
    /// Block Header (cryptographically relevant data only)
    pub block_header: BlockHeader,

    /// This block's cryptographic hash (serialized header)
    pub block_hash: [u8; 64],

    /// Application-specific block data (opaque to this library)
    pub block_data: Vec<u8>,
}

impl Block {
    /// Regular constructor for Block
    pub fn new_regular_block(parent_hash: [u8; 64], block_data: Vec<u8>) -> Self {
        let (block_header, block_hash) = BlockHeader::new(parent_hash);
        Self {
            block_header,
            block_hash,
            block_data,
        }
    }
    /// Genesis block constructor
    pub fn new_genesis_block(block_data: Vec<u8>) -> Self {
        let (block_header, block_hash) = BlockHeader::new([0u8; 64]);
        Self {
            block_header,
            block_hash,
            block_data,
        }
    }

    /// Deserialize a Block from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        // Header: uid(16) + version(4) + parent_hash(64) + timestamp(8) + nonce(8) = 100 bytes
        // Hash: 64 bytes
        // Data length: 4 bytes
        // Minimum: 100 + 64 + 4 = 168 bytes
        const DATA_LENGTH_LEN: usize = 4;
        const HASH_LEN: usize = 64;
        const MINIMUM_LEN: usize = BLOCK_HEADER_SIZE + HASH_LEN + DATA_LENGTH_LEN;
        let mut index = 0;
        if data.len() < MINIMUM_LEN {
            return Err(anyhow!("Not enough data for header, hash, and length"));
        }
        // Deserialize header (100 bytes total)
        let block_header = BlockHeader::new_from_bytes(&data[index..index + BLOCK_HEADER_SIZE])?;
        index += BLOCK_HEADER_SIZE;

        // Deserialize block hash (64 bytes)
        let mut block_hash = [0u8; HASH_LEN];
        block_hash.copy_from_slice(&data[index..index + HASH_LEN]);
        index += HASH_LEN;

        // Deserialize block data length (4 bytes)
        let data_len =
            u32::from_le_bytes(data[index..index + DATA_LENGTH_LEN].try_into().unwrap()) as usize;
        index += DATA_LENGTH_LEN;
        if data.len() < index + data_len {
            return Err(anyhow!("Not enough space for block data")); // Not enough data for block data
        }
        // Deserialize block data
        let block_data = data[index..index + data_len].to_vec();
        Ok(Block {
            block_header,
            block_hash,
            block_data,
        })
    }

    /// Serialize Block to bytes
    pub fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // Serialize header
        bytes.extend_from_slice(&self.block_header.bytes());
        // Serialize block hash
        bytes.extend_from_slice(&self.block_hash);
        // Serialize block data length
        let data_len = self.block_data.len() as u32;
        bytes.extend_from_slice(&data_len.to_le_bytes());
        // Serialize block data
        bytes.extend_from_slice(&self.block_data);
        bytes
    }
}
