//! Blockchain storage and management using RocksDB
//!
//! This module provides persistent storage for blockchain blocks using RocksDB,
//! a high-performance embedded database. The blockchain automatically manages
//! block heights and parent relationships, storing blocks by UUID with a
//! separate height index for efficient retrieval.
//!
//! # Database Structure
//!
//! The blockchain uses two RocksDB column families:
//! - `blocks`: Maps block UUID (16 bytes) to serialized Block data
//! - `height`: Maps block height (u64 as big-endian bytes) to block UUID
//!
//! # Concurrency
//!
//! The `current_height` field is protected by a `Mutex` to allow safe
//! concurrent access. This represents the next height to be assigned.

use crate::block::{BLOCK_HASH_SIZE, BLOCK_UID_SIZE, Block};
use crate::db_model::RocksDbModel;
use anyhow::{Context, Result, anyhow};
use openssl::pkey::PKey;
use openssl::rsa::Padding;
use openssl::symm::Cipher;
use rocksdb::{DB, IteratorMode};
use secrecy::{ExposeSecret, SecretBox, zeroize::Zeroize};
use std::fmt;
use std::path::Path;
use std::sync::Mutex;

pub const AES_KEY_LEN_SIZE: usize = 4; // u32 for AES key length
pub const AES_GCM_256_KEY_SIZE: usize = 32; // 256 bits
pub const AES_GCM_NONCE_SIZE: usize = 12; // 96 bits
pub const AES_GCM_TAG_SIZE: usize = 16; // 128 bits
pub const BLOCK_LEN_SIZE: usize = 4; // u32 for block length

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
///
/// A securely stored private key that implements Zeroize
#[derive(Clone)]
struct SecurePrivateKey {
    der_bytes: Vec<u8>,
}

impl Zeroize for SecurePrivateKey {
    fn zeroize(&mut self) {
        self.der_bytes.zeroize();
    }
}

impl fmt::Debug for SecurePrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecurePrivateKey")
            .field("der_bytes", &"<redacted>")
            .finish()
    }
}
pub struct BlockChain {
    /// RocksDB database instance
    db: std::sync::Arc<DB>,

    /// Next height to be assigned (protected by Mutex for thread safety)
    /// When inserting a new block, it will be assigned this height,
    /// then this value is incremented.
    current_height: Mutex<u64>,

    /// Secured Private key for decrypting block data
    private_key: SecretBox<SecurePrivateKey>,

    /// Public key for encrypting block data
    pub public_key: PKey<openssl::pkey::Public>,
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
        let db = RocksDbModel::new(path.as_ref().to_path_buf())
            .with_column_family("blocks")
            .with_column_family("height")
            .open()
            .map_err(|e| anyhow!("Failed to open RocksDB: {}", e))?;

        let db = std::sync::Arc::new(db);

        // Get the next height to assign based on the highest block in the database
        let height_cf = db
            .cf_handle("height")
            .ok_or_else(|| anyhow!("Failed to get height column family"))?;

        let next_height = {
            let mut iter = db.iterator_cf(height_cf, IteratorMode::End);
            match iter.next() {
                Some(Ok((height_bytes, _block_uuid))) => {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&height_bytes);
                    // Last block is at this height, so next block should be height + 1
                    u64::from_be_bytes(bytes) + 1
                }
                _ => 0, // Empty blockchain, start at height 0
            }
        };

        // Load private key from PEM file

        let (private_key_der, public_key) =
            (|| -> Result<(Vec<u8>, PKey<openssl::pkey::Public>)> {
                let pem_path = private_key_path
                    .as_ref()
                    .to_str()
                    .ok_or_else(|| anyhow!("Invalid private key path"))?;

                let pem_data = std::fs::read(pem_path)
                    .with_context(|| format!("Failed to read private key from {}", pem_path))?;

                use std::io::Write;
                print!("Enter password for private key (press Enter if none): ");
                std::io::stdout().flush()?;
                let pwd = rpassword::read_password()?;

                let key = if !pwd.is_empty() {
                    PKey::private_key_from_pem_passphrase(&pem_data, pwd.as_bytes())
                        .context("Failed to decrypt private key with password")?
                } else {
                    PKey::private_key_from_pem(&pem_data)
                        .context("Failed to parse private key PEM")?
                };
                let public_der_bytes = key
                    .public_key_to_der()
                    .context("Failed to extract public key to DER")?;
                let private_der_bytes = key
                    .private_key_to_der()
                    .context("Failed to convert private key to DER")?;

                let public_key = PKey::public_key_from_der(&public_der_bytes)
                    .context("Failed to reconstruct public key from DER")?;

                Ok((private_der_bytes, public_key))
            })()?;

        Ok(Self {
            db,
            current_height: Mutex::new(next_height),
            private_key: SecretBox::new(Box::new(SecurePrivateKey {
                der_bytes: private_key_der,
            })),
            public_key,
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
    ///
    // The format of the block storded in the database is:
    // RSA Encrypted AES key (variable length) || AES-GCM nonce (12 bytes) || AES-GCM tag (16 bytes) || AES-GCM ciphertext (variable length)
    pub fn put_block(&self, block_data: Vec<u8>) -> Result<()> {
        let mut height = self.current_height.lock().unwrap();
        let (encrypted_aes_key, encrypted_block_data, nonce, tag) =
            (|| -> Result<(Vec<u8>, Vec<u8>, [u8; AES_GCM_NONCE_SIZE], [u8; AES_GCM_TAG_SIZE])> {
                // Generate random AES-256 key (32 bytes)
                let mut aes_key = [0u8; AES_GCM_256_KEY_SIZE];
                openssl::rand::rand_bytes(&mut aes_key)
                    .map_err(|e| anyhow!("Failed to generate random AES key: {}", e))?;

                // Generate random 12-byte nonce
                let mut nonce = [0u8; AES_GCM_NONCE_SIZE];
                openssl::rand::rand_bytes(&mut nonce)
                    .map_err(|e| anyhow!("Failed to generate random nonce: {}", e))?;

                let cipher = Cipher::aes_256_gcm();
                let mut tag = [0u8; AES_GCM_TAG_SIZE];

                let encrypted_block_data = openssl::symm::encrypt_aead(
                    cipher,
                    &aes_key,
                    Some(&nonce),
                    &[],
                    &block_data,
                    &mut tag,
                )
                .map_err(|e| anyhow!("AES-GCM encryption failed: {}", e))?;

                // Encrypt AES key with RSA-OAEP
                let encrypted_aes_key = (|| -> Result<Vec<u8>> {
                    let rsa = self
                        .public_key
                        .rsa()
                        .map_err(|e| anyhow!("Failed to get RSA key: {}", e))?;
                    let mut ciphertext = vec![0u8; rsa.size() as usize];
                    let len = rsa
                        .public_encrypt(&aes_key, &mut ciphertext, Padding::PKCS1_OAEP)
                        .map_err(|e| anyhow!("RSA encryption failed: {}", e))?;

                    ciphertext.truncate(len);
                    Ok(ciphertext)
                })()?;
                Ok((encrypted_aes_key, encrypted_block_data, nonce, tag))
            })()?;
        let block = if *height == 0 {
            Block::new_genesis_block(encrypted_block_data)
        } else {
            // Get the previous block (at height - 1)
            let parent_block = self.get_block_by_height(*height - 1)?;
            let parent_hash = parent_block.block_hash;
            Block::new_regular_block(parent_hash, encrypted_block_data)
        };
        use crate::block::BLOCK_UID_SIZE;
        let (uuid, stored_block_bytes) = (|| -> Result<([u8; BLOCK_UID_SIZE], Vec<u8>)> {
            let stored_block_bytes = {
                let mut bytes = Vec::new();
                let key_len = encrypted_aes_key.len() as u32;
                // Append length of encrypted AES key (4 bytes)
                bytes.extend_from_slice(&key_len.to_le_bytes());
                // Append encrypted AES key
                bytes.extend_from_slice(&encrypted_aes_key);
                // Append nonce
                bytes.extend_from_slice(&nonce);
                // Append tag
                bytes.extend_from_slice(&tag);
                // Append Block
                let block_bytes = block.bytes();
                let block_len = block_bytes.len() as u32;
                bytes.extend_from_slice(&block_len.to_le_bytes());
                bytes.extend_from_slice(&block_bytes);
                bytes
            };
            Ok((block.block_header.block_uid, stored_block_bytes))
        })()?;

        // Store block by UUID
        let blocks_cf = self
            .db
            .cf_handle("blocks")
            .ok_or_else(|| anyhow!("Failed to get blocks column family"))?;
        self.db
            .put_cf(blocks_cf, uuid, &stored_block_bytes)
            .map_err(|e| anyhow!("Failed to insert block: {}", e))?;

        // Store height -> UUID mapping
        let height_bytes = height.to_be_bytes();
        let height_cf = self
            .db
            .cf_handle("height")
            .ok_or_else(|| anyhow!("Failed to get height column family"))?;
        self.db
            .put_cf(height_cf, &height_bytes, &block.block_header.block_uid)
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
    pub fn get_block_by_height(&self, height: u64) -> Result<Block> {
        let height_bytes = height.to_be_bytes();
        let height_cf = self
            .db
            .cf_handle("height")
            .ok_or_else(|| anyhow!("Failed to get height column family"))?;

        let stored_block = match self
            .db
            .get_cf(height_cf, &height_bytes)
            .map_err(|e| anyhow!("Failed to get block UUID by height: {}", e))?
        {
            Some(uuid_bytes) => {
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(&uuid_bytes);
                let blocks_cf = self
                    .db
                    .cf_handle("blocks")
                    .ok_or_else(|| anyhow!("Failed to get blocks column family"))?;

                match self
                    .db
                    .get_cf(blocks_cf, &uuid)
                    .map_err(|e| anyhow!("Failed to get block by UUID: {}", e))?
                {
                    Some(block_bytes) => block_bytes,
                    None => {
                        return Err(anyhow!(
                            "Block UUID {:?} not found in blocks column family",
                            uuid
                        ));
                    }
                }
            }
            None => return Err(anyhow!("No block found at height {}", height)),
        };
        let block = (|| -> Result<Block> {
            // Deserialize block from bytes
            let mut index: usize = 0;

            // Validate minimum size
            if stored_block.len() < AES_KEY_LEN_SIZE {
                return Err(anyhow!(
                    "Stored block too small: {} bytes (need at least {})",
                    stored_block.len(),
                    AES_KEY_LEN_SIZE
                ));
            }

            let aes_key_len =
                u32::from_le_bytes(stored_block[index..AES_KEY_LEN_SIZE].try_into().unwrap())
                    as usize;
            index += AES_KEY_LEN_SIZE;

            // Validate we have enough data for encrypted AES key
            if stored_block.len() < index + aes_key_len {
                return Err(anyhow!(
                    "Not enough data for encrypted AES key: need {} bytes at offset {}, have {} total",
                    aes_key_len,
                    index,
                    stored_block.len()
                ));
            }

            let encrypted_aes_key = &stored_block[index..index + aes_key_len];
            index += aes_key_len;

            // Validate we have enough data for nonce and tag
            if stored_block.len() < index + AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE + BLOCK_LEN_SIZE {
                return Err(anyhow!(
                    "Not enough data for nonce, tag, and block length at offset {}, have {} total",
                    index,
                    stored_block.len()
                ));
            }

            let nonce = &stored_block[index..index + AES_GCM_NONCE_SIZE];
            index += AES_GCM_NONCE_SIZE;
            let tag = &stored_block[index..index + AES_GCM_TAG_SIZE];
            index += AES_GCM_TAG_SIZE;
            let block_len = u32::from_le_bytes(
                stored_block[index..index + BLOCK_LEN_SIZE]
                    .try_into()
                    .unwrap(),
            ) as usize;
            index += BLOCK_LEN_SIZE;

            // Validate we have enough data for the serialized block
            if stored_block.len() < index + block_len {
                return Err(anyhow!(
                    "Not enough data for serialized block: need {} bytes at offset {}, have {} total",
                    block_len,
                    index,
                    stored_block.len()
                ));
            }

            let block_bytes = &stored_block[index..index + block_len];
            let mut block = Block::from_bytes(block_bytes).map_err(|e| {
                anyhow!(
                    "Failed to deserialize block: {} (block_bytes len: {}, expected in block: {})",
                    e,
                    block_bytes.len(),
                    block_len
                )
            })?;
            let decrypted_block_data = {
                // Decrypt AES key with RSA-OAEP
                let aes_key = (|| -> Result<Vec<u8>> {
                    let rsa = self.private_key.expose_secret().der_bytes.as_slice();
                    let pkey = PKey::private_key_from_der(rsa)
                        .map_err(|e| anyhow!("Failed to reconstruct private key: {}", e))?;
                    let rsa = pkey
                        .rsa()
                        .map_err(|e| anyhow!("Failed to get RSA key: {}", e))?;
                    let mut plaintext = vec![0u8; rsa.size() as usize];
                    let len = rsa
                        .private_decrypt(encrypted_aes_key, &mut plaintext, Padding::PKCS1_OAEP)
                        .map_err(|e| anyhow!("RSA decryption failed: {}", e))?;
                    plaintext.truncate(len);
                    Ok(plaintext)
                })()?;

                // Decrypt block data with AES-GCM
                let decrypted_data = openssl::symm::decrypt_aead(
                    Cipher::aes_256_gcm(),
                    &aes_key,
                    Some(nonce),
                    &[],
                    &block.block_data,
                    tag,
                )
                .map_err(|e| anyhow!("AES-GCM decryption failed: {}", e))?;
                decrypted_data
            };
            block.block_data = decrypted_block_data;
            Ok(block)
        })()?;

        Ok(block)
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
        let height_cf = self
            .db
            .cf_handle("height")
            .ok_or_else(|| anyhow!("Failed to get height column family"))?;

        let mut iter = self.db.iterator_cf(height_cf, IteratorMode::End);
        match iter.next() {
            Some(Ok((height_bytes, _))) => {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&height_bytes);
                Ok(u64::from_be_bytes(bytes))
            }
            _ => Ok(0), // Empty blockchain
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
    pub fn get_latest_block(&self) -> Result<Block> {
        let height = *self.current_height.lock().unwrap();
        if height == 0 {
            Err(anyhow!("No blocks in blockchain"))
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
    pub fn block_exists(&self, uuid: &[u8; BLOCK_UID_SIZE]) -> Result<bool> {
        let blocks_cf = self
            .db
            .cf_handle("blocks")
            .ok_or_else(|| anyhow!("Failed to get blocks column family"))?;

        Ok(self
            .db
            .get_cf(blocks_cf, uuid)
            .map_err(|e| anyhow!("Failed to check block existence: {}", e))?
            .is_some())
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
    pub fn get_block_by_uuid(&self, uuid: &[u8; BLOCK_UID_SIZE]) -> Result<Option<Block>> {
        let blocks_cf = self
            .db
            .cf_handle("blocks")
            .ok_or_else(|| anyhow!("Failed to get blocks column family"))?;

        match self
            .db
            .get_cf(blocks_cf, uuid)
            .map_err(|e| anyhow!("Failed to get block by UUID: {}", e))?
        {
            Some(block_bytes) => {
                let block = Block::from_bytes(&block_bytes)
                    .map_err(|e| anyhow!("Failed to deserialize block: {}", e))?;
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
        let blocks_cf = self
            .db
            .cf_handle("blocks")
            .ok_or_else(|| anyhow!("Failed to get blocks column family"))?;
        let count = self.db.iterator_cf(blocks_cf, IteratorMode::Start).count();
        Ok(count)
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
                if block.block_header.parent_hash != [0u8; BLOCK_HASH_SIZE] {
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
        let current_height = *self.current_height.lock().unwrap();
        let max_height = if current_height > 0 {
            current_height - 1
        } else {
            0
        };
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
    /// Maximum height to iterate to (inclusive)
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
            Ok(b) => Some(Ok(b)),
            Err(e) => Some(Err(e)),
        }
    }
}
