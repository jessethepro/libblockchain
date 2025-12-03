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
//! let chain = BlockChain::new("./blockchain_data", "./app_private_key.pem")?;
//!
//! // Insert blocks (height is automatic)
//! chain.insert_block(b"Genesis data".to_vec())?;
//! chain.insert_block(b"Block 1 data".to_vec())?;
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

    /// Secure container for the application's private key
    app_key_store: crate::app_key_store::AppKeyStore,
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
    /// * `private_key_path` - Path to the PEM file containing the application's private key
    ///
    /// # Returns
    /// A `BlockChain` instance with recovered state
    ///
    /// # Errors
    /// Returns an error if:
    /// - The database cannot be opened or created
    /// - The required trees cannot be opened
    /// - The height index cannot be read
    /// - The private key cannot be loaded
    pub fn new<P: AsRef<Path>>(path: P, private_key_path: P) -> Result<Self> {
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
        // Initialize the application key store (for decrypting block data)
        let app_key_store = crate::app_key_store::AppKeyStore::from_pem_file(
            private_key_path
                .as_ref()
                .to_str()
                .ok_or_else(|| anyhow!("Invalid private key path"))?,
            None,
        )?;

        Ok(Self {
            db,
            blocks,
            height_index,
            current_height: Mutex::new(next_height),
            app_key_store,
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
    pub fn insert_block(&self, block_data: Vec<u8>) -> Result<()> {
        let mut height = self.current_height.lock().unwrap();

        let block = if *height == 0 {
            Block::new_genesis_block(block_data, &self.app_key_store.public_key)
        } else {
            // Get the previous block (at height - 1)
            let parent_hash = self
                .get_block_by_height(*height - 1)?
                .ok_or_else(|| anyhow!("No parent block found for non-genesis block"))?
                .block_hash;
            Block::new_regular_block(parent_hash, block_data, &self.app_key_store.public_key)
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

    /// Get the encrypted block data at a specific height
    ///
    /// Retrieves the block at the given height and returns only its encrypted
    /// `block_data` field. This is useful when you only need the data payload
    /// without the full block structure.
    ///
    /// # Arguments
    /// * `height` - The block height to query
    ///
    /// # Returns
    /// - `Ok(Some(Vec<u8>))` - The encrypted block data if block exists
    /// - `Ok(None)` - If no block exists at this height
    /// - `Err(_)` - If a database or deserialization error occurs
    ///
    /// # Example
    /// ```no_run
    /// # use libblockchain::blockchain::BlockChain;
    /// # fn example(chain: &BlockChain) -> anyhow::Result<()> {
    /// if let Some(encrypted_data) = chain.get_data_at_height(5)? {
    ///     // Use encrypted_data (decrypt with Block::get_block_data)
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_data_at_height(&self, height: u64) -> Result<Option<Vec<u8>>> {
        match self.get_block_by_height(height)? {
            Some(block) => Ok(Some(block.block_data)),
            None => Ok(None),
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
                let block = deserialize_block(&block_bytes)?;
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

    /// Validate the entire blockchain for integrity
    ///
    /// Uses the `BlockIterator` to traverse all blocks in height order,
    /// checking each block's cryptographic integrity and chain linkage.
    ///
    /// Validates:
    /// - Genesis block (height 0) has a zero parent hash
    /// - All subsequent blocks correctly link to their parent's hash
    /// - Each block's hash matches its computed value from the header
    /// - The chain has no gaps (iterator ensures sequential heights)
    ///
    /// # Returns
    /// - `Ok(())` if the blockchain is valid
    /// - `Err(_)` with details if validation fails
    ///
    /// # Example
    /// ```no_run
    /// # use libblockchain::blockchain::BlockChain;
    /// # fn example(chain: &BlockChain) -> anyhow::Result<()> {
    /// chain.validate()?;
    /// println!("Blockchain is valid!");
    /// # Ok(())
    /// # }
    /// ```
    pub fn validate(&self) -> Result<()> {
        let mut previous_block: Option<Block> = None;
        let mut height = 0u64;

        for block_result in self.iter() {
            let block = block_result?;

            // Validate genesis block
            if height == 0 {
                if block.block_header.parent_hash != [0u8; 64] {
                    return Err(anyhow!(
                        "Genesis block has non-zero parent hash: {:?}",
                        block.block_header.parent_hash
                    ));
                }
            } else {
                // Validate parent link
                let prev = previous_block
                    .as_ref()
                    .ok_or_else(|| anyhow!("Internal error: missing previous block"))?;

                if block.block_header.parent_hash != prev.block_hash {
                    return Err(anyhow!(
                        "Block at height {} has invalid parent hash. Expected {:?}, got {:?}",
                        height,
                        prev.block_hash,
                        block.block_header.parent_hash
                    ));
                }
            }

            if block.block_hash != block.block_header.generate_block_hash() {
                return Err(anyhow!("Block hash mismatch at height {}", height));
            }

            previous_block = Some(block);
            height += 1;
        }

        Ok(())
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
    use openssl::pkey::{PKey, Private};
    use openssl::rsa::Rsa;
    use tempfile::TempDir;

    fn generate_rsa_keypair(bits: usize) -> Result<PKey<Private>> {
        let rsa =
            Rsa::generate(bits as u32).map_err(|e| anyhow!("Failed to generate RSA key: {}", e))?;

        PKey::from_rsa(rsa).map_err(|e| anyhow!("Failed to create PKey from RSA: {}", e))
    }

    /// Helper to save a private key to a PEM file in the temp directory
    fn save_private_key_pem(dir: &Path, private_key: &PKey<Private>) -> Result<std::path::PathBuf> {
        let key_path = dir.join("test_private_key.pem");
        let pem_bytes = private_key
            .private_key_to_pem_pkcs8()
            .map_err(|e| anyhow!("Failed to convert key to PEM: {}", e))?;
        std::fs::write(&key_path, pem_bytes)
            .map_err(|e| anyhow!("Failed to write key file: {}", e))?;
        Ok(key_path)
    }

    #[test]
    fn test_sled_db_creation() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let key_path = save_private_key_pem(temp_dir.path(), &private_key)
            .expect("Failed to save private key");

        let db = BlockChain::new(temp_dir.path(), &key_path).expect("Failed to create BlockChain");

        assert_eq!(db.block_count().unwrap(), 0);
    }

    #[test]
    fn test_insert_and_retrieve_block() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let key_path = save_private_key_pem(temp_dir.path(), &private_key)
            .expect("Failed to save private key");
        let db = BlockChain::new(temp_dir.path(), &key_path).expect("Failed to create BlockChain");

        db.insert_block(b"Genesis data".to_vec())
            .expect("Failed to insert block");

        let retrieved = db
            .get_block_by_height(0)
            .expect("Failed to get block")
            .expect("Block not found");

        assert_eq!(retrieved.block_header.parent_hash, [0u8; 64]);
    }

    #[test]
    fn test_get_block_by_height() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let key_path = save_private_key_pem(temp_dir.path(), &private_key)
            .expect("Failed to save private key");
        let db = BlockChain::new(temp_dir.path(), &key_path).expect("Failed to create BlockChain");

        db.insert_block(b"Genesis".to_vec())
            .expect("Failed to insert genesis");
        db.insert_block(b"Block 1".to_vec())
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
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let key_path = save_private_key_pem(temp_dir.path(), &private_key)
            .expect("Failed to save private key");
        let db = BlockChain::new(temp_dir.path(), &key_path).expect("Failed to create BlockChain");

        db.insert_block(b"Genesis".to_vec())
            .expect("Failed to insert genesis");
        db.insert_block(b"Block 1".to_vec())
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
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let key_path = save_private_key_pem(temp_dir.path(), &private_key)
            .expect("Failed to save private key");
        let db = BlockChain::new(temp_dir.path(), &key_path).expect("Failed to create BlockChain");

        assert_eq!(db.block_count().unwrap(), 0);

        db.insert_block(b"Genesis".to_vec())
            .expect("Failed to insert genesis");

        assert_eq!(db.block_count().unwrap(), 1);

        db.insert_block(b"Block 1".to_vec())
            .expect("Failed to insert block 1");

        assert_eq!(db.block_count().unwrap(), 2);
    }

    #[test]
    fn test_iterator() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let key_path = save_private_key_pem(temp_dir.path(), &private_key)
            .expect("Failed to save private key");
        let db = BlockChain::new(temp_dir.path(), &key_path).expect("Failed to create BlockChain");

        // Create a blockchain with 5 blocks
        db.insert_block(b"Genesis".to_vec())
            .expect("Failed to insert genesis");

        for i in 1..5 {
            db.insert_block(format!("Block {}", i).into_bytes())
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
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let key_path = save_private_key_pem(temp_dir.path(), &private_key)
            .expect("Failed to save private key");
        let db = BlockChain::new(temp_dir.path(), &key_path).expect("Failed to create BlockChain");

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
        let key_path =
            save_private_key_pem(path, &private_key).expect("Failed to save private key");

        // Create blockchain and add blocks
        {
            let db = BlockChain::new(path, &key_path).expect("Failed to create BlockChain");
            db.insert_block(b"Genesis".to_vec())
                .expect("Failed to insert genesis");
            db.insert_block(b"Block 1".to_vec())
                .expect("Failed to insert block 1");
            db.insert_block(b"Block 2".to_vec())
                .expect("Failed to insert block 2");

            assert_eq!(db.block_count().unwrap(), 3);
            drop(db); // Explicitly close the database
        }

        // Reopen blockchain and verify it recovers state correctly
        {
            let db = BlockChain::new(path, &key_path).expect("Failed to reopen BlockChain");

            // Verify existing blocks are still there
            assert_eq!(db.block_count().unwrap(), 3);
            assert!(db.get_block_by_height(0).unwrap().is_some());
            assert!(db.get_block_by_height(1).unwrap().is_some());
            assert!(db.get_block_by_height(2).unwrap().is_some());

            // Add a new block - should be at height 3
            db.insert_block(b"Block 3".to_vec())
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

    #[test]
    fn test_validate_valid_chain() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let key_path = save_private_key_pem(temp_dir.path(), &private_key)
            .expect("Failed to save private key");
        let db = BlockChain::new(temp_dir.path(), &key_path).expect("Failed to create BlockChain");

        // Empty chain should be valid
        db.validate().expect("Empty blockchain should be valid");

        // Add blocks
        db.insert_block(b"Genesis".to_vec())
            .expect("Failed to insert genesis");
        db.validate()
            .expect("Blockchain with genesis should be valid");

        db.insert_block(b"Block 1".to_vec())
            .expect("Failed to insert block 1");
        db.validate()
            .expect("Blockchain with 2 blocks should be valid");

        db.insert_block(b"Block 2".to_vec())
            .expect("Failed to insert block 2");
        db.validate()
            .expect("Blockchain with 3 blocks should be valid");
    }

    #[test]
    fn test_validate_after_persistence() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let path = temp_dir.path();

        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let key_path =
            save_private_key_pem(path, &private_key).expect("Failed to save private key");

        // Create blockchain with blocks
        {
            let db = BlockChain::new(path, &key_path).expect("Failed to create BlockChain");
            db.insert_block(b"Genesis".to_vec())
                .expect("Failed to insert genesis");
            db.insert_block(b"Block 1".to_vec())
                .expect("Failed to insert block 1");
            db.insert_block(b"Block 2".to_vec())
                .expect("Failed to insert block 2");
            db.validate()
                .expect("Blockchain should be valid before close");
            drop(db); // Explicitly close the database
        }

        // Reopen and validate
        {
            let db = BlockChain::new(path, &key_path).expect("Failed to reopen BlockChain");
            db.validate()
                .expect("Blockchain should be valid after reopen");
        }
    }

    #[test]
    fn test_get_data_at_height() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let key_path = save_private_key_pem(temp_dir.path(), &private_key)
            .expect("Failed to save private key");
        let db = BlockChain::new(temp_dir.path(), &key_path).expect("Failed to create BlockChain");

        // Insert blocks with different data
        let data0 = b"Genesis block data".to_vec();
        let data1 = b"First block data".to_vec();
        let data2 = b"Second block data".to_vec();

        db.insert_block(data0.clone())
            .expect("Failed to insert genesis");
        db.insert_block(data1.clone())
            .expect("Failed to insert block 1");
        db.insert_block(data2.clone())
            .expect("Failed to insert block 2");

        // Test getting data at different heights
        let encrypted_data0 = db
            .get_data_at_height(0)
            .expect("Failed to get data at height 0")
            .expect("No data at height 0");
        let encrypted_data1 = db
            .get_data_at_height(1)
            .expect("Failed to get data at height 1")
            .expect("No data at height 1");
        let encrypted_data2 = db
            .get_data_at_height(2)
            .expect("Failed to get data at height 2")
            .expect("No data at height 2");

        // Verify data is encrypted (not equal to plaintext)
        assert_ne!(encrypted_data0, data0);
        assert_ne!(encrypted_data1, data1);
        assert_ne!(encrypted_data2, data2);

        // Decrypt and verify
        use crate::hybrid_encryption::hybrid_decrypt;

        let decrypted0 =
            hybrid_decrypt(&private_key, encrypted_data0).expect("Failed to decrypt data 0");
        let decrypted1 =
            hybrid_decrypt(&private_key, encrypted_data1).expect("Failed to decrypt data 1");
        let decrypted2 =
            hybrid_decrypt(&private_key, encrypted_data2).expect("Failed to decrypt data 2");

        assert_eq!(decrypted0, data0);
        assert_eq!(decrypted1, data1);
        assert_eq!(decrypted2, data2);

        // Test non-existent height
        assert!(
            db.get_data_at_height(99)
                .expect("Failed to query height 99")
                .is_none()
        );
    }
}
