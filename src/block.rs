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
use std::time::{SystemTime, UNIX_EPOCH};
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
    height: u64,

    /// Unique identifier (UUID v4) for this block
    block_uid: [u8; 16],

    /// Header version to support future upgrades (currently 1)
    version: u32,

    /// SHA-512 hash of the parent block (all zeros for genesis)
    parent_hash: [u8; 64],

    /// Timestamp of block creation
    timestamp: u64,
}

impl BlockHeader {
    pub fn new(parent_hash: Vec<u8>, height: u64) -> Self {
        use uuid::Uuid;
        if parent_hash.len() != BLOCK_HASH_SIZE {
            panic!(
                "Invalid parent_hash length: expected {}, got {}",
                BLOCK_HASH_SIZE,
                parent_hash.len()
            );
        }
        let mut parent_hash_array = [0u8; BLOCK_HASH_SIZE];
        parent_hash_array.copy_from_slice(&parent_hash);

        let block_uid = Uuid::new_v4().as_bytes().to_owned();
        let version = BLOCK_VERSION;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        Self {
            height,
            block_uid,
            version,
            parent_hash: parent_hash_array,
            timestamp,
        }
    }

    fn height(&self) -> u64 {
        self.height
    }
    fn block_uid(&self) -> Vec<u8> {
        self.block_uid.to_vec()
    }
    fn version(&self) -> u32 {
        self.version
    }
    fn parent_hash(&self) -> Vec<u8> {
        self.parent_hash.to_vec()
    }
    fn timestamp(&self) -> SystemTime {
        UNIX_EPOCH + std::time::Duration::from_secs(self.timestamp)
    }
    fn new_from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != 100 {
            return Err(anyhow!(
                "Invalid data length for BlockHeader: expected 100, got {}",
                data.len()
            ));
        }
        let mut index = 0;

        let height = u64::from_le_bytes(
            data.get(index..index + BLOCK_HEIGHT_SIZE)
                .and_then(|s| s.try_into().ok())
                .expect("Failed to read height from block header"),
        );
        index += BLOCK_HEIGHT_SIZE;

        let block_uid = {
            let mut uid = [0u8; BLOCK_UID_SIZE];
            uid.copy_from_slice(
                data.get(index..index + BLOCK_UID_SIZE)
                    .expect("Failed to read block_uid from header"),
            );
            index += BLOCK_UID_SIZE;
            uid
        };
        let version = u32::from_le_bytes(
            data.get(index..index + BLOCK_VERSION_SIZE)
                .and_then(|s| s.try_into().ok())
                .expect("Failed to read version from block header"),
        );
        index += BLOCK_VERSION_SIZE;
        let parent_hash = {
            let mut phash = [0u8; BLOCK_HASH_SIZE];
            phash.copy_from_slice(
                data.get(index..index + BLOCK_HASH_SIZE)
                    .expect("Failed to read parent_hash from header"),
            );
            index += BLOCK_HASH_SIZE;
            phash
        };

        let timestamp = u64::from_le_bytes(
            data.get(index..index + BLOCK_TIMESTAMP_SIZE)
                .and_then(|s| s.try_into().ok())
                .expect("Failed to read timestamp from block header"),
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
    block_header: BlockHeader,

    /// SHA-512 hash of the block header (64 bytes)
    block_hash: [u8; 64],

    /// Application-specific data (opaque to this library)
    ///
    /// In memory: plaintext application data
    /// In database: hybrid encrypted format requiring application's private key to decrypt
    block_data: Vec<u8>,
}

impl Block {
    /// Create a regular (non-genesis) block
    ///
    /// # Arguments
    /// * `height` - Block height in chain (must be > 0)
    /// * `parent_hash` - SHA-512 hash of the parent block
    /// * `block_data` - Application-specific data (will be encrypted when stored)
    pub fn new_regular_block(height: u64, parent_hash: Vec<u8>, block_data: Vec<u8>) -> Self {
        let block_header = BlockHeader::new(parent_hash, height);
        let mut hashing_data = Vec::from(block_header.bytes());
        hashing_data.extend_from_slice(&block_data);
        let block_hash = openssl::hash::hash(MessageDigest::sha512(), &hashing_data)
            .expect("Failed to compute block hash")
            .as_ref()
            .try_into()
            .expect("Hash length mismatch");
        Self {
            block_header,
            block_hash,
            block_data,
        }
    }

    pub fn new_genesis_block(block_data: Vec<u8>) -> Self {
        // Genesis block has height 0 and parent hash of all zeros.
        Self::new_regular_block(0, vec![0u8; 64], block_data)
    }

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
        let block_header = BlockHeader::new_from_bytes(
            data.get(index..index + BLOCK_HEADER_SIZE)
                .ok_or_else(|| anyhow!("Not enough data for block header"))?,
        )?;
        index += BLOCK_HEADER_SIZE;

        // Deserialize block hash (64 bytes)
        let mut block_hash = [0u8; HASH_LEN];
        block_hash.copy_from_slice(
            data.get(index..index + HASH_LEN)
                .ok_or_else(|| anyhow!("Not enough data for block hash"))?,
        );
        index += HASH_LEN;

        // Deserialize block data length (4 bytes)
        let data_len = u32::from_le_bytes(
            data.get(index..index + DATA_LENGTH_LEN)
                .and_then(|s| s.try_into().ok())
                .ok_or_else(|| anyhow!("Not enough data for block data length"))?,
        ) as usize;
        index += DATA_LENGTH_LEN;
        if data.len() < index + data_len {
            return Err(anyhow!("Not enough space for block data")); // Not enough data for block data
        }
        // Deserialize block data
        let block_data = data
            .get(index..index + data_len)
            .ok_or_else(|| anyhow!("Not enough space for block data"))?
            .to_vec();
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
    pub fn block_hash(&self) -> Vec<u8> {
        self.block_hash.to_vec()
    }
    pub fn parent_hash(&self) -> Vec<u8> {
        self.block_header.parent_hash()
    }
    pub fn height(&self) -> u64 {
        self.block_header.height()
    }
    pub fn block_uid(&self) -> Vec<u8> {
        self.block_header.block_uid()
    }
    pub fn version(&self) -> u32 {
        self.block_header.version()
    }
    pub fn timestamp(&self) -> SystemTime {
        self.block_header.timestamp()
    }
    pub fn block_data(&self) -> Vec<u8> {
        self.block_data.clone()
    }
    pub fn header_bytes(&self) -> Vec<u8> {
        self.block_header.bytes()
    }
}
