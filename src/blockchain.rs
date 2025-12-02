//! Blockchain storage and management using SledDB
//!
//! This module provides persistent storage for blockchain blocks using Sled,
//! a high-performance embedded database. The blockchain automatically manages
//! block heights and parent relationships, storing blocks by UUID with a
//! separate height index for efficient retrieval.
//!
//! # Database Structure
//!
//! The blockchain uses two SledDB trees:
//! - `blocks`: Maps block UUID (16 bytes) to serialized Block data
//! - `height`: Maps block height (u64 as big-endian bytes) to block UUID
//!
//! # Concurrency
//!
//! The `current_height` field is protected by a `Mutex` to allow safe
//! concurrent access. This represents the next height to be assigned.
//!
//! # Example
//!
//! ```no_run
//! use libblockchain::blockchain::BlockChain;
//! # use openssl::x509::X509;
//!
//! # fn example() -> anyhow::Result<()> {
//! // Create or open a blockchain
//! let chain = BlockChain::new("./blockchain_data")?;
//!
//! // Insert blocks (height is automatic)
//! # let cert: X509 = unsafe { std::mem::zeroed() };
//! chain.insert_block(b"Genesis data".to_vec(), cert.clone())?;
//! chain.insert_block(b"Block 1 data".to_vec(), cert)?;
//!
//! // Retrieve blocks by height
//! let block = chain.get_block_by_height(0)?.unwrap();
//!
//! // Iterate over all blocks
//! for block in chain.iter() {
//!     let block = block?;
//!     println!("Block hash: {:?}", block.block_hash);
//! }
//! # Ok(())
//! # }
//! ```

use crate::block::{Block, deserialize_block};
use crate::db_model::SledDb;
use anyhow::{Result, anyhow};
use openssl::x509::X509;
use std::path::Path;
use std::sync::Mutex;

/// SledDB-backed blockchain storage with automatic height management
///
/// This structure maintains a persistent blockchain using SledDB's embedded
/// key-value store. Blocks are stored by UUID, and a separate index maps
/// heights to UUIDs for efficient sequential access.
///
/// # Thread Safety
///
/// The `BlockChain` can be safely shared across threads. The `current_height`
/// field is protected by a `Mutex` to ensure consistent height assignment.
pub struct BlockChain {
    /// Sled database instance
    db: sled::Db,

    /// Tree for storing blocks by UUID
    /// Key: block UUID (16 bytes), Value: serialized Block
    blocks: sled::Tree,

    /// Tree for storing height -> UUID mapping
    /// Key: block height (u64 as big-endian bytes), Value: block UUID (16 bytes)
    height_index: sled::Tree,

    /// Next height to be assigned (protected by Mutex for thread safety)
    /// When inserting a new block, it will be assigned this height,
    /// then this value is incremented.
    current_height: Mutex<u64>,
}

impl BlockChain {
    /// Open or create a new blockchain database
    ///
    /// Opens an existing blockchain at the specified path, or creates a new one
    /// if it doesn't exist. Automatically recovers the current height from the
    /// database by scanning the height index.
    ///
    /// # Arguments
    /// * `path` - Path to the database directory
    ///
    /// # Returns
    /// A `BlockChain` instance with recovered state
    ///
    /// # Errors
    /// Returns an error if:
    /// - The database cannot be opened or created
    /// - The required trees cannot be opened
    /// - The height index cannot be read
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = SledDb::new(path.as_ref().to_path_buf())
            .open()
            .map_err(|e| anyhow!("Failed to open SledDB: {}", e))?;

        // blocks tree. Key: block uuid (UUID v4), Value: serialized Block
        let blocks = db
            .open_tree("blocks")
            .map_err(|e| anyhow!("Failed to open blocks tree: {}", e))?;
        // height_index tree. Key: block height (u64 as bytes), Value: block uuid (UUID v4)
        let height_index = db
            .open_tree("height")
            .map_err(|e| anyhow!("Failed to open height_index tree: {}", e))?;

        // Get the next height to assign based on the highest block in the database
        let next_height = match height_index
            .last()
            .map_err(|e| anyhow!("Failed to get last height: {}", e))?
        {
            Some((height_bytes, _block_uuid)) => {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&height_bytes);
                // Last block is at this height, so next block should be height + 1
                u64::from_be_bytes(bytes) + 1
            }
            None => 0, // Empty blockchain, start at height 0
        };

        Ok(Self {
            db,
            blocks,
            height_index,
            current_height: Mutex::new(next_height),
        })
    }

    /// Insert a new block into the blockchain
    ///
    /// Automatically determines whether to create a genesis block (if current_height == 0)
    /// or a regular block (linking to the previous block). The height is assigned
    /// automatically and incremented after insertion.
    ///
    /// # Arguments
    /// * `block_data` - The raw data to store in the block (will be encrypted)
    /// * `app_cert` - X509 certificate used for hybrid encryption of block data
    ///
    /// # Returns
    /// `Ok(())` on success
    ///
    /// # Errors
    /// Returns an error if:
    /// - The parent block cannot be found (for non-genesis blocks)
    /// - Block serialization fails
    /// - Database insertion fails
    /// - Database flush fails
    pub fn insert_block(&self, block_data: Vec<u8>, app_cert: X509) -> Result<()> {
        let mut height = self.current_height.lock().unwrap();

        let block = if *height == 0 {
            Block::new_genesis_block(block_data, app_cert)
        } else {
            // Get the previous block (at height - 1)
            let parent_hash = self
                .get_block_by_height(*height - 1)?
                .ok_or_else(|| anyhow!("No parent block found for non-genesis block"))?
                .block_hash;
            Block::new_regular_block(parent_hash, block_data, app_cert)
        };

        let block_bytes = block.serialize_block();

        // Store block by UUID
        self.blocks
            .insert(&block.block_header.block_uid, block_bytes)
            .map_err(|e| anyhow!("Failed to insert block: {}", e))?;

        // Store height -> UUID mapping
        let height_bytes = height.to_be_bytes();
        self.height_index
            .insert(height_bytes, &block.block_header.block_uid)
            .map_err(|e| anyhow!("Failed to insert height index: {}", e))?;

        // Increment height for next block
        *height += 1;

        // Flush to ensure durability
        self.db
            .flush()
            .map_err(|e| anyhow!("Failed to flush database: {}", e))?;

        Ok(())
    }

    /// Retrieve a block by its height in the chain
    ///
    /// # Arguments
    /// * `height` - The block height (0 for genesis, 1 for first block after genesis, etc.)
    ///
    /// # Returns
    /// - `Ok(Some(Block))` if a block exists at this height
    /// - `Ok(None)` if no block exists at this height
    /// - `Err(_)` if a database or deserialization error occurs
    pub fn get_block_by_height(&self, height: u64) -> Result<Option<Block>> {
        let height_bytes = height.to_be_bytes();

        match self
            .height_index
            .get(height_bytes)
            .map_err(|e| anyhow!("Failed to get height index: {}", e))?
        {
            Some(uuid_bytes) => {
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(&uuid_bytes);
                self.get_block_by_uuid(&uuid)
            }
            None => Ok(None),
        }
    }

    /// Get the height of the last block in the chain
    ///
    /// Returns the maximum height value in the height index. For an empty
    /// blockchain, returns 0. Note that this reads from the database index,
    /// not from the `current_height` mutex.
    ///
    /// # Returns
    /// The height of the last block, or 0 for an empty chain
    pub fn get_height(&self) -> Result<u64> {
        match self
            .height_index
            .last()
            .map_err(|e| anyhow!("Failed to get last height: {}", e))?
        {
            Some((height_bytes, _)) => {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&height_bytes);
                Ok(u64::from_be_bytes(bytes))
            }
            None => Ok(0), // Empty blockchain
        }
    }

    /// Get the most recently inserted block
    ///
    /// Returns the block at the highest height (current_height - 1).
    /// Returns `None` for an empty blockchain.
    ///
    /// # Returns
    /// - `Ok(Some(Block))` if blocks exist
    /// - `Ok(None)` if the blockchain is empty
    /// - `Err(_)` if a database or deserialization error occurs
    pub fn get_latest_block(&self) -> Result<Option<Block>> {
        let height = *self.current_height.lock().unwrap();
        if height == 0 {
            Ok(None)
        } else {
            self.get_block_by_height(height - 1)
        }
    }

    /// Check if a block with the given UUID exists in the database
    ///
    /// # Arguments
    /// * `uuid` - The block's UUID (16 bytes)
    ///
    /// # Returns
    /// `Ok(true)` if the block exists, `Ok(false)` otherwise
    pub fn block_exists(&self, uuid: &[u8; 16]) -> Result<bool> {
        self.blocks
            .contains_key(uuid)
            .map_err(|e| anyhow!("Failed to check block existence: {}", e))
    }

    /// Retrieve a block by its UUID
    ///
    /// Directly queries the blocks tree using the UUID as the key.
    ///
    /// # Arguments
    /// * `uuid` - The block's UUID (16 bytes)
    ///
    /// # Returns
    /// - `Ok(Some(Block))` if the block exists
    /// - `Ok(None)` if no block with this UUID exists
    /// - `Err(_)` if a database or deserialization error occurs
    pub fn get_block_by_uuid(&self, uuid: &[u8; 16]) -> Result<Option<Block>> {
        match self
            .blocks
            .get(uuid)
            .map_err(|e| anyhow!("Failed to get block by UUID: {}", e))?
        {
            Some(block_bytes) => {
                let block = deserialize_block(&block_bytes)
                    .ok_or_else(|| anyhow!("Failed to deserialize block"))?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Get the total number of blocks stored in the blockchain
    ///
    /// # Returns
    /// The count of blocks in the database
    pub fn block_count(&self) -> Result<usize> {
        Ok(self.blocks.len())
    }

    /// Create an iterator over all blocks in the blockchain, ordered by height
    ///
    /// The iterator starts at height 0 and continues to the current maximum height.
    /// Blocks are yielded in ascending height order (genesis first).
    ///
    /// # Returns
    /// A `BlockIterator` that yields `Result<Block>` in ascending height order
    ///
    /// # Example
    /// ```no_run
    /// # use libblockchain::blockchain::BlockChain;
    /// # fn example(chain: &BlockChain) -> anyhow::Result<()> {
    /// for block_result in chain.iter() {
    ///     let block = block_result?;
    ///     println!("Block: {:?}", block.block_hash);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn iter(&self) -> BlockIterator<'_> {
        let max_height = *self.current_height.lock().unwrap();
        BlockIterator {
            db: self,
            current_height: 0,
            max_height,
        }
    }
}

/// Iterator over blocks in the blockchain, ordered by height
///
/// This iterator traverses blocks sequentially from height 0 to the maximum
/// height captured at iterator creation. Blocks inserted after the iterator
/// is created will not be included.
///
/// Each iteration queries the database by height, so blocks are guaranteed
/// to be in chain order.
pub struct BlockIterator<'a> {
    /// Reference to the blockchain database
    db: &'a BlockChain,
    /// Current position in the iteration
    current_height: u64,
    /// Maximum height to iterate to (inclusive, but needs -1 adjustment)
    max_height: u64,
}

impl<'a> Iterator for BlockIterator<'a> {
    type Item = Result<Block>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_height > self.max_height {
            return None;
        }

        let block = self.db.get_block_by_height(self.current_height);
        self.current_height += 1;

        match block {
            Ok(Some(b)) => Some(Ok(b)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::pkey::{PKey, Private};
    use openssl::rsa::Rsa;
    use openssl::x509::{X509Builder, X509NameBuilder};
    use tempfile::TempDir;

    fn generate_rsa_keypair(bits: usize) -> Result<PKey<Private>> {
        let rsa =
            Rsa::generate(bits as u32).map_err(|e| anyhow!("Failed to generate RSA key: {}", e))?;

        PKey::from_rsa(rsa).map_err(|e| anyhow!("Failed to create PKey from RSA: {}", e))
    }

    fn generate_test_cert(private_key: &PKey<Private>) -> Result<openssl::x509::X509> {
        let mut builder =
            X509Builder::new().map_err(|e| anyhow!("Failed to create X509 builder: {}", e))?;

        builder
            .set_version(2)
            .map_err(|e| anyhow!("Failed to set version: {}", e))?;

        let serial = BigNum::from_u32(1).map_err(|e| anyhow!("Failed to create serial: {}", e))?;
        let serial = serial
            .to_asn1_integer()
            .map_err(|e| anyhow!("Failed to convert serial: {}", e))?;
        builder
            .set_serial_number(&serial)
            .map_err(|e| anyhow!("Failed to set serial: {}", e))?;

        let mut name_builder =
            X509NameBuilder::new().map_err(|e| anyhow!("Failed to create name builder: {}", e))?;
        name_builder
            .append_entry_by_text("CN", "Test Certificate")
            .map_err(|e| anyhow!("Failed to set CN: {}", e))?;
        let name = name_builder.build();
        builder
            .set_subject_name(&name)
            .map_err(|e| anyhow!("Failed to set subject: {}", e))?;
        builder
            .set_issuer_name(&name)
            .map_err(|e| anyhow!("Failed to set issuer: {}", e))?;

        let not_before = Asn1Time::days_from_now(0)
            .map_err(|e| anyhow!("Failed to create not_before: {}", e))?;
        let not_after = Asn1Time::days_from_now(365)
            .map_err(|e| anyhow!("Failed to create not_after: {}", e))?;
        builder
            .set_not_before(&not_before)
            .map_err(|e| anyhow!("Failed to set not_before: {}", e))?;
        builder
            .set_not_after(&not_after)
            .map_err(|e| anyhow!("Failed to set not_after: {}", e))?;

        builder
            .set_pubkey(private_key)
            .map_err(|e| anyhow!("Failed to set public key: {}", e))?;

        builder
            .sign(private_key, MessageDigest::sha256())
            .map_err(|e| anyhow!("Failed to sign certificate: {}", e))?;

        Ok(builder.build())
    }

    #[test]
    fn test_sled_db_creation() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let db = BlockChain::new(temp_dir.path()).expect("Failed to create BlockChain");

        assert_eq!(db.block_count().unwrap(), 0);
    }

    #[test]
    fn test_insert_and_retrieve_block() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let db = BlockChain::new(temp_dir.path()).expect("Failed to create BlockChain");

        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let cert = generate_test_cert(&private_key).expect("Failed to generate certificate");

        db.insert_block(b"Genesis data".to_vec(), cert)
            .expect("Failed to insert block");

        let retrieved = db
            .get_block_by_height(0)
            .expect("Failed to get block")
            .expect("Block not found");

        assert_eq!(retrieved.block_header.parent_hash, [0u8; 32]);
    }

    #[test]
    fn test_get_block_by_height() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let db = BlockChain::new(temp_dir.path()).expect("Failed to create BlockChain");

        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let cert = generate_test_cert(&private_key).expect("Failed to generate certificate");

        db.insert_block(b"Genesis".to_vec(), cert.clone())
            .expect("Failed to insert genesis");
        db.insert_block(b"Block 1".to_vec(), cert)
            .expect("Failed to insert block 1");

        let retrieved = db
            .get_block_by_height(1)
            .expect("Failed to get block")
            .expect("Block not found");

        let genesis = db
            .get_block_by_height(0)
            .expect("Failed to get genesis")
            .expect("Genesis not found");

        assert_eq!(retrieved.block_header.parent_hash, genesis.block_hash);
    }

    #[test]
    fn test_get_latest_block() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let db = BlockChain::new(temp_dir.path()).expect("Failed to create BlockChain");

        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let cert = generate_test_cert(&private_key).expect("Failed to generate certificate");

        db.insert_block(b"Genesis".to_vec(), cert.clone())
            .expect("Failed to insert genesis");
        db.insert_block(b"Block 1".to_vec(), cert)
            .expect("Failed to insert block 1");

        let latest = db
            .get_latest_block()
            .expect("Failed to get latest block")
            .expect("No latest block");

        let block1 = db
            .get_block_by_height(1)
            .expect("Failed to get block 1")
            .expect("Block 1 not found");

        assert_eq!(latest.block_hash, block1.block_hash);
    }

    #[test]
    fn test_block_count() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let db = BlockChain::new(temp_dir.path()).expect("Failed to create BlockChain");

        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let cert = generate_test_cert(&private_key).expect("Failed to generate certificate");

        assert_eq!(db.block_count().unwrap(), 0);

        db.insert_block(b"Genesis".to_vec(), cert.clone())
            .expect("Failed to insert genesis");

        assert_eq!(db.block_count().unwrap(), 1);

        db.insert_block(b"Block 1".to_vec(), cert)
            .expect("Failed to insert block 1");

        assert_eq!(db.block_count().unwrap(), 2);
    }

    #[test]
    fn test_iterator() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let db = BlockChain::new(temp_dir.path()).expect("Failed to create BlockChain");

        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let cert = generate_test_cert(&private_key).expect("Failed to generate certificate");

        // Create a blockchain with 5 blocks
        db.insert_block(b"Genesis".to_vec(), cert.clone())
            .expect("Failed to insert genesis");

        for i in 1..5 {
            db.insert_block(format!("Block {}", i).into_bytes(), cert.clone())
                .expect(&format!("Failed to insert block {}", i));
        }

        // Iterate over all blocks
        let blocks: Vec<_> = db
            .iter()
            .collect::<Result<Vec<_>>>()
            .expect("Failed to collect blocks");

        assert_eq!(blocks.len(), 5);

        // Verify blocks are in order
        for i in 1..blocks.len() {
            assert_eq!(blocks[i].block_header.parent_hash, blocks[i - 1].block_hash);
        }
    }

    #[test]
    fn test_empty_iterator() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let db = BlockChain::new(temp_dir.path()).expect("Failed to create BlockChain");

        let blocks: Vec<_> = db
            .iter()
            .collect::<Result<Vec<_>>>()
            .expect("Failed to collect blocks");

        assert_eq!(blocks.len(), 0);
    }

    #[test]
    fn test_blockchain_persistence() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let path = temp_dir.path();

        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let cert = generate_test_cert(&private_key).expect("Failed to generate certificate");

        // Create blockchain and add blocks
        {
            let db = BlockChain::new(path).expect("Failed to create BlockChain");
            db.insert_block(b"Genesis".to_vec(), cert.clone())
                .expect("Failed to insert genesis");
            db.insert_block(b"Block 1".to_vec(), cert.clone())
                .expect("Failed to insert block 1");
            db.insert_block(b"Block 2".to_vec(), cert.clone())
                .expect("Failed to insert block 2");

            assert_eq!(db.block_count().unwrap(), 3);
        }

        // Reopen blockchain and verify it recovers state correctly
        {
            let db = BlockChain::new(path).expect("Failed to reopen BlockChain");

            // Verify existing blocks are still there
            assert_eq!(db.block_count().unwrap(), 3);
            assert!(db.get_block_by_height(0).unwrap().is_some());
            assert!(db.get_block_by_height(1).unwrap().is_some());
            assert!(db.get_block_by_height(2).unwrap().is_some());

            // Add a new block - should be at height 3
            db.insert_block(b"Block 3".to_vec(), cert.clone())
                .expect("Failed to insert block 3");

            assert_eq!(db.block_count().unwrap(), 4);
            let block3 = db
                .get_block_by_height(3)
                .unwrap()
                .expect("Block 3 not found");
            let block2 = db
                .get_block_by_height(2)
                .unwrap()
                .expect("Block 2 not found");

            // Verify block 3 links to block 2
            assert_eq!(block3.block_header.parent_hash, block2.block_hash);
        }
    }
}
