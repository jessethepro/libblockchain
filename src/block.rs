//! Block structure for a blockchain implementation.
//!
//! This module defines the core block data structures used in the blockchain:
//! - `BlockHeader`: Contains cryptographically-relevant metadata (height, UUID, version, parent hash, timestamp)
//! - `Block`: Complete block with header, hash, and encrypted application data
//!
//! Blocks are linked through parent hashes to form an immutable chain. Each block's
//! hash is computed from its header using SHA-512.

pub const BLOCK_HEIGHT_SIZE: usize = 8; // u64 size in bytes
pub const BLOCK_VERSION: u32 = 1;
pub const BLOCK_UID_SIZE: usize = 16; // UUID size in bytes
pub const BLOCK_VERSION_SIZE: usize = 4; // u32 size in bytes
pub const BLOCK_HASH_SIZE: usize = 64; // SHA-512 hash size in bytes
pub const BLOCK_TIMESTAMP_SIZE: usize = 8; // u64 size in bytes
pub const BLOCK_HEADER_SIZE: usize = BLOCK_HEIGHT_SIZE
    + BLOCK_UID_SIZE
    + BLOCK_VERSION_SIZE
    + BLOCK_HASH_SIZE
    + BLOCK_TIMESTAMP_SIZE; // height + uid + version + parent_hash + timestamp
use anyhow::{Result, anyhow};
use openssl::hash::MessageDigest;
/// Block header containing cryptographically-relevant metadata
///
/// The header is hashed with SHA-512 to produce the block's hash, which
/// serves as its cryptographic identity and links it to child blocks.
///
/// # Serialization Format
///
/// Fixed 100-byte format:
/// ```text
/// height(8) || block_uid(16) || version(4) || parent_hash(64) || timestamp(8)
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    /// Height of the block in the blockchain (0 for genesis)
    pub height: u64,

    /// Unique identifier (UUID v4) for this block
    pub block_uid: [u8; 16],

    /// Header version to support future upgrades (currently 1)
    pub version: u32,

    /// SHA-512 hash of the parent block (all zeros for genesis)
    pub parent_hash: [u8; 64],

    /// Timestamp of block creation (UNIX epoch seconds)
    pub timestamp: u64,
}

impl BlockHeader {
    /// Create a new block header with computed hash
    ///
    /// Generates a UUID v4 identifier and current timestamp automatically.
    /// Computes SHA-512 hash of the serialized header.
    ///
    /// # Arguments
    /// * `parent_hash` - SHA-512 hash of parent block (use `[0u8; 64]` for genesis)
    /// * `height` - Block height in chain (0 for genesis, increments for each block)
    ///
    /// # Returns
    /// Tuple of (BlockHeader, block_hash)
    pub fn new(parent_hash: [u8; BLOCK_HASH_SIZE], height: u64) -> (Self, [u8; BLOCK_HASH_SIZE]) {
        use std::time::{SystemTime, UNIX_EPOCH};
        use uuid::Uuid;

        let block_uid = Uuid::new_v4().as_bytes().to_owned();
        let version = BLOCK_VERSION;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        let header = Self {
            height: height,
            block_uid,
            version,
            parent_hash,
            timestamp,
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

    /// Deserialize a BlockHeader from bytes
    ///
    /// # Arguments
    /// * `data` - Exactly 100 bytes in the format: height(8) || uid(16) || version(4) || parent_hash(64) || timestamp(8)
    ///
    /// # Errors
    /// Returns error if data is not exactly 100 bytes
    pub fn new_from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != 100 {
            return Err(anyhow!(
                "Invalid data length for BlockHeader: expected 100, got {}",
                data.len()
            ));
        }
        let mut index = 0;

        let height = u64::from_le_bytes(data[index..index + BLOCK_HEIGHT_SIZE].try_into().unwrap());
        index += BLOCK_HEIGHT_SIZE;

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

        Ok(BlockHeader {
            height,
            block_uid,
            version,
            parent_hash,
            timestamp,
        })
    }

    /// Serialize the header to bytes (100 bytes fixed)
    ///
    /// Format: height(8) || uid(16) || version(4) || parent_hash(64) || timestamp(8)
    pub fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.height.to_le_bytes());
        bytes.extend_from_slice(&self.block_uid);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.parent_hash);
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes
    }

    /// Generate SHA-512 hash of this header
    ///
    /// This is the block's cryptographic identity used for linking child blocks.
    pub fn generate_block_hash(&self) -> [u8; 64] {
        let hash_vec = openssl::hash::hash(MessageDigest::sha512(), &self.bytes())
            .expect("SHA-512 hashing failed")
            .to_vec();
        let mut hash = [0u8; 64];
        hash.copy_from_slice(&hash_vec[..64]);
        hash
    }
}

/// Complete block with header, hash, and application data
///
/// Blocks are the fundamental unit of the blockchain. Each block contains:
/// - A header with cryptographic metadata
/// - A SHA-512 hash computed from the header
/// - Application-specific data (only this field is encrypted in storage)
///
/// # Serialization Format
///
/// ```text
/// header(100) || block_hash(64) || data_len(4) || block_data(variable)
/// ```
///
/// Note: When stored in the database, `block_data` is replaced with encrypted data:
/// ```text
/// header(100) || block_hash(64) || [aes_key_len(4) || RSA-OAEP(aes_key)(var) || nonce(12) || tag(16) || data_len(4) || AES-GCM(data)(var)]
/// ```
#[derive(Debug, Clone)]
pub struct Block {
    /// Block header with cryptographic metadata
    pub block_header: BlockHeader,

    /// SHA-512 hash of the block header (64 bytes)
    pub block_hash: [u8; 64],

    /// Application-specific data (opaque to this library)
    ///
    /// In memory: plaintext application data
    /// In database: hybrid encrypted format requiring application's private key to decrypt
    pub block_data: Vec<u8>,
}

impl Block {
    /// Create a regular (non-genesis) block
    ///
    /// # Arguments
    /// * `height` - Block height in chain (must be > 0)
    /// * `parent_hash` - SHA-512 hash of the parent block
    /// * `block_data` - Application-specific data (will be encrypted when stored)
    pub fn new_regular_block(height: u64, parent_hash: [u8; 64], block_data: Vec<u8>) -> Self {
        let (block_header, block_hash) = BlockHeader::new(parent_hash, height);
        Self {
            block_header,
            block_hash,
            block_data,
        }
    }

    /// Create a genesis block (height 0, no parent)
    ///
    /// Genesis blocks have height 0 and parent_hash of all zeros.
    ///
    /// # Arguments
    /// * `block_data` - Application-specific data (will be encrypted when stored)
    pub fn new_genesis_block(block_data: Vec<u8>) -> Self {
        // Genesis block has height 0 and parent hash of all zeros.
        let (block_header, block_hash) = BlockHeader::new([0u8; 64], 0);
        Self {
            block_header,
            block_hash,
            block_data,
        }
    }

    /// Deserialize a Block from bytes
    ///
    /// # Format
    /// ```text
    /// header(100) || block_hash(64) || data_len(4) || block_data(variable)
    /// ```
    /// Minimum size: 168 bytes (100 + 64 + 4)
    ///
    /// # Errors
    /// Returns error if data is too short or malformed
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        // Header: height(8) + uid(16) + version(4) + parent_hash(64) + timestamp(8) = 100 bytes
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
    ///
    /// Format: header(100) || block_hash(64) || data_len(4) || block_data(variable)
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
