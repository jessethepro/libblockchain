//! Blockchain storage and management using RocksDB
//!
//! This module provides persistent storage for blockchain blocks using RocksDB,
//! a high-performance embedded database. The blockchain automatically manages
//! block heights and parent relationships, storing blocks by height for
//! efficient retrieval and sequential access.
//!
//! **Note**: RocksDB is compiled from source with the `mt_static` feature for
//! multi-threaded static linking. This ensures thread-safe operation without
//! requiring system-installed RocksDB libraries.
//!
//! # Database Structure
//!
//! The blockchain uses one RocksDB column family:
//! - `blocks`: Maps block height (u64 as little-endian bytes) to encrypted Block data
//!
//! # Storage Format
//!
//! Blocks are serialized as:
//! ```text
//! BlockHeader(100) || BlockHash(64) || EncryptedBlockData(variable)
//! ```
//!
//! Only the block_data field is encrypted with hybrid encryption:
//! ```text
//! [aes_key_len(4)] || [RSA-OAEP(aes_key)(var)] || [nonce(12)] || [tag(16)] || [data_len(4)] || [AES-GCM(data)(var)]
//! ```
//!
//! The application's private key is required to RSA-OAEP decrypt the AES key,
//! which is then used to AES-GCM decrypt the actual block data.
//!
//! # Key Management
//!
//! Private keys are stored in the Linux kernel keyring for secure, isolated storage.
//! The blockchain reads keys from the process keyring using `keyutils`. Keys must
//! be added to the keyring before creating the blockchain instance.
//!
//! # Concurrency
//!
//! The database is thread-safe. RocksDB handles concurrent reads efficiently,
//! while writes are serialized internally.

use crate::block::{BLOCK_HASH_SIZE, BLOCK_HEIGHT_SIZE, Block};
use crate::db_model::RocksDbModel;
use anyhow::{Result, anyhow};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Padding;
use openssl::symm::Cipher;
use rocksdb::{DB, IteratorMode};
use secrecy::{ExposeSecret, SecretBox};
use std::path::Path;

pub const AES_KEY_LEN_SIZE: usize = 4; // u32 for AES key length
pub const AES_GCM_256_KEY_SIZE: usize = 32; // 256 bits
pub const AES_GCM_NONCE_SIZE: usize = 12; // 96 bits
pub const AES_GCM_TAG_SIZE: usize = 16; // 128 bits
pub const DATA_LEN_SIZE: usize = 4; // u32 for block length

/// RocksDB-backed blockchain storage with automatic height management
///
/// This structure maintains a persistent blockchain using RocksDB's embedded
/// key-value store. Blocks are stored directly by height (u64) as the key,
/// enabling efficient sequential access via RocksDB's native iterator.
///
/// # Key Storage
///
/// Private keys are stored in the Linux kernel keyring (accessed via `keyutils`).
/// The blockchain reads keys from the process keyring by name. Keys remain
/// isolated in kernel memory and are never written to disk.
///
/// # Thread Safety
///
/// The `BlockChain` is thread-safe. Multiple readers can access blocks
/// concurrently, while RocksDB serializes write operations internally.
pub struct BlockChain {
    /// RocksDB database instance
    db: DB,

    /// The App Private key for decrypting block data is stored in a SecretBox for security
    app_key: SecretBox<Vec<u8>>,

    /// The App Public key for encrypting block data
    public_key: PKey<openssl::pkey::Public>,
}

impl BlockChain {
    /// Open or create a new blockchain database
    ///
    /// Opens an existing blockchain at the specified path, or creates a new one
    /// if it doesn't exist.
    ///
    /// # Arguments
    /// * `path` - Path to the database directory
    /// * `proc_keyring` - Linux kernel keyring containing the application's private key
    /// * `app_key_name` - Name of the key in the keyring (e.g., "my-app-key")
    ///
    /// # Returns
    /// A `BlockChain` instance ready for use
    ///
    /// # Errors
    /// Returns an error if:
    /// - The database cannot be opened or created
    /// - The private key cannot be found in the keyring
    /// - The private key data cannot be read or parsed
    ///
    /// # Key Requirements
    ///
    /// The keyring must contain a key with DER-encoded private key data.
    /// Use `keyctl` to add keys to the process keyring:
    /// ```bash
    /// keyctl padd user my-app-key @p < private_key.der
    /// ```
    ///
    /// # Example
    /// ```no_run
    /// use libblockchain::blockchain::BlockChain;
    /// use keyutils::{Keyring, SpecialKeyring};
    /// # fn example() -> anyhow::Result<()> {
    /// let keyring = Keyring::attach(SpecialKeyring::Process)?;
    /// let chain = BlockChain::new("./my_blockchain", keyring, "my-app-key".to_string())?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new<P: AsRef<Path>>(path: P, app_key: PKey<openssl::pkey::Private>) -> Result<Self> {
        let db = RocksDbModel::new(path.as_ref().to_path_buf())
            .with_column_family("blocks")
            .with_column_family("signatures")
            .open()
            .map_err(|e| anyhow!("Failed to open RocksDB: {}", e))?;
        // Load public key from the keyring
        let public_key = app_key
            .public_key_to_der()
            .and_then(|der| PKey::public_key_from_der(&der))
            .map_err(|e| anyhow!("Failed to extract public key DER: {}", e))?;

        Ok(Self {
            db,
            app_key: SecretBox::new(Box::new(
                app_key
                    .private_key_to_der()
                    .map_err(|e| anyhow!("Failed to serialize private key to DER format: {}", e))?,
            )),
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
    /// `Ok(u64)` - The Height of the newly inserted block on success
    ///
    /// # Errors
    /// Returns an error if:
    /// - The parent block cannot be found (for non-genesis blocks)
    /// - Block serialization fails
    /// - Database insertion fails
    /// - Database flush fails
    ///
    // Only block_data is encrypted. Block format in database:
    // BlockHeader(100) || BlockHash(64) || EncryptedBlockData(variable)
    //
    // EncryptedBlockData format:
    // aes_key_len(4) || RSA-OAEP(aes_key)(var) || nonce(12) || tag(16) || data_len(4) || AES-GCM(data)(var)
    pub fn put_block(&self, block_data: Vec<u8>) -> Result<u64> {
        let encrypted_block_data = (|| -> Result<Vec<u8>> {
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
                let rsa = (|| -> Result<openssl::rsa::Rsa<openssl::pkey::Public>> {
                    let rsa = self
                        .public_key
                        .rsa()
                        .map_err(|e| anyhow!("Failed to get RSA key: {}", e))?;
                    Ok(rsa)
                })()?;
                let mut ciphertext = vec![0u8; rsa.size() as usize];
                let len = rsa
                    .public_encrypt(&aes_key, &mut ciphertext, Padding::PKCS1_OAEP)
                    .map_err(|e| anyhow!("RSA encryption failed: {}", e))?;

                ciphertext.truncate(len);
                Ok(ciphertext)
            })()?;
            let serialized_block_data = {
                let mut data = Vec::new();
                let aes_key_len = encrypted_aes_key.len() as u32;
                data.extend_from_slice(&aes_key_len.to_le_bytes());
                data.extend_from_slice(&encrypted_aes_key);
                data.extend_from_slice(&nonce);
                data.extend_from_slice(&tag);
                let data_len = encrypted_block_data.len() as u32;
                data.extend_from_slice(&data_len.to_le_bytes());
                data.extend_from_slice(&encrypted_block_data);
                data
            };
            Ok(serialized_block_data)
        })()?;
        let block_count = self.block_count()?;
        let block = if block_count == 0 {
            Block::new_genesis_block(encrypted_block_data)
        } else {
            // Get the previous block which is 1 less than block count
            let parent_block = self.get_block_by_height(block_count - 1)?;
            let parent_hash = parent_block.block_hash;
            Block::new_regular_block(block_count, parent_hash, encrypted_block_data)
        };
        let height = block.block_header.height;
        // Store block by UUID
        let blocks_cf = self
            .db
            .cf_handle("blocks")
            .ok_or_else(|| anyhow!("Failed to get blocks column family"))?;
        self.db
            .put_cf(blocks_cf, height.to_le_bytes(), block.bytes())
            .map_err(|e| anyhow!("Failed to insert block: {}", e))?;

        // Flush to ensure durability
        self.db
            .flush()
            .map_err(|e| anyhow!("Failed to flush database: {}", e))?;

        Ok(block.block_header.height)
    }

    pub fn put_signature(&self, height: u64, signature: Vec<u8>) -> Result<u64> {
        let signatures_cf = self
            .db
            .cf_handle("signatures")
            .ok_or_else(|| anyhow!("Failed to get signatures column family"))?;
        self.db
            .put_cf(signatures_cf, height.to_le_bytes(), &signature)
            .map_err(|e| anyhow!("Failed to insert signature: {}", e))?;
        Ok(height)
    }

    /// Retrieve a block by its height in the chain
    ///
    /// # Arguments
    /// * `height` - The block height (0 for genesis, 1 for first block after genesis, etc.)
    ///
    /// # Returns
    /// - `Ok(Block)` if a block exists at this height
    /// - `Err(_)` if no block exists at this height or a database/deserialization error occurs
    pub fn get_block_by_height(&self, height: u64) -> Result<Block> {
        let blocks_cf = self
            .db
            .cf_handle("blocks")
            .ok_or_else(|| anyhow!("Failed to get blocks column family"))?;
        let block = (|| -> Result<Block> {
            let block_bytes = self
                .db
                .get_cf(blocks_cf, height.to_le_bytes())
                .map_err(|e| anyhow!("Failed to get block by height: {}", e))?
                .ok_or_else(|| anyhow!("No block found at height {}", height))?;
            let stored_height = u64::from_le_bytes(
                block_bytes
                    .get(0..BLOCK_HEIGHT_SIZE)
                    .and_then(|s| s.try_into().ok())
                    .ok_or_else(|| anyhow!("Failed to read height from stored block"))?,
            );
            if height != stored_height {
                return Err(anyhow!(
                    "Block height mismatch: expected {}, got {}",
                    height,
                    stored_height
                ));
            }
            let mut block = Block::from_bytes(&block_bytes)?;
            block.block_data = self.decrypt_block_data(&block.block_data)?;
            Ok(block)
        })()?;
        Ok(block)
    }

    pub fn get_signature_by_height(&self, height: u64) -> Result<Vec<u8>> {
        let signatures_cf = self
            .db
            .cf_handle("signatures")
            .ok_or_else(|| anyhow!("Failed to get signatures column family"))?;
        let signature = self
            .db
            .get_cf(signatures_cf, height.to_le_bytes())
            .map_err(|e| anyhow!("Failed to get signature by height: {}", e))?
            .ok_or_else(|| anyhow!("No signature found at height {}", height))?;
        Ok(signature)
    }

    fn decrypt_block_data(&self, encrypted_block_data: &[u8]) -> Result<Vec<u8>> {
        let mut index = 0;
        let aes_key_len = u32::from_le_bytes(
            encrypted_block_data
                .get(index..index + AES_KEY_LEN_SIZE)
                .and_then(|s| s.try_into().ok())
                .ok_or_else(|| anyhow!("Failed to read AES key length"))?,
        ) as usize;
        index += AES_KEY_LEN_SIZE;
        let encrypted_aes_key = encrypted_block_data
            .get(index..index + aes_key_len)
            .ok_or_else(|| anyhow!("Failed to read encrypted AES key"))?;
        index += aes_key_len;
        let nonce = encrypted_block_data
            .get(index..index + AES_GCM_NONCE_SIZE)
            .ok_or_else(|| anyhow!("Failed to read nonce"))?;
        index += AES_GCM_NONCE_SIZE;
        let tag = encrypted_block_data
            .get(index..index + AES_GCM_TAG_SIZE)
            .ok_or_else(|| anyhow!("Failed to read authentication tag"))?;
        index += AES_GCM_TAG_SIZE;
        let data_len = u32::from_le_bytes(
            encrypted_block_data
                .get(index..index + DATA_LEN_SIZE)
                .and_then(|s| s.try_into().ok())
                .ok_or_else(|| anyhow!("Failed to read data length"))?,
        ) as usize;
        index += DATA_LEN_SIZE;
        let data_bytes = encrypted_block_data
            .get(index..index + data_len)
            .ok_or_else(|| anyhow!("Failed to read encrypted data"))?;
        let decrypted_data = {
            // Decrypt AES key with RSA-OAEP
            let aes_key = (|| -> Result<Vec<u8>> {
                let app_private_key =
                    PKey::private_key_from_der(self.app_key.expose_secret().as_slice())
                        .map_err(|e| anyhow!("Failed to parse private key DER: {}", e))?;
                let rsa = app_private_key
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

            openssl::symm::decrypt_aead(
                Cipher::aes_256_gcm(),
                &aes_key,
                Some(nonce),
                &[],
                data_bytes,
                tag,
            )
            .map_err(|e| anyhow!("AES-GCM decryption failed: {}", e))?
        };
        Ok(decrypted_data)
    }

    /// Get the height of the last block in the chain
    ///
    /// Returns the maximum height value in the height index. For an empty
    /// blockchain, returns 0. Note that this reads from the database index,
    /// not from the `current_height` mutex.
    ///
    /// # Returns
    /// `Ok(u64)` - The height of the last block (0-indexed), or 0 for an empty chain
    pub fn get_max_height(&self) -> Result<u64> {
        let count = self.block_count()?;
        if count == 0 { Ok(0) } else { Ok(count - 1) }
    }

    /// Delete the most recently inserted block
    ///
    /// Deletes the block at the highest height (current_height - 1).
    /// Returns the UUID of the deleted block.
    ///
    /// # Returns
    /// - `Ok(Some([u8; BLOCK_UID_SIZE]))` - UUID of the deleted block if blocks exist
    /// - `Ok(None)` - If the blockchain is empty
    /// - `Err(_)` - If a database or deserialization error occurs
    pub fn delete_latest_block(&self) -> Result<Option<u64>> {
        let block_count = self.block_count()?;
        match block_count {
            0 => {
                // Blockchain is empty
                return Ok(None);
            }
            _ => {
                // Proceed to delete the latest block
                // Delete block from blocks column family
                let blocks_cf = self
                    .db
                    .cf_handle("blocks")
                    .ok_or_else(|| anyhow!("Failed to get blocks column family"))?;
                self.db
                    .delete_cf(blocks_cf, (block_count - 1).to_le_bytes())
                    .map_err(|e| anyhow!("Failed to delete block: {}", e))?;
                let signatures_cf = self
                    .db
                    .cf_handle("signatures")
                    .ok_or_else(|| anyhow!("Failed to get signatures column family"))?;
                self.db
                    .delete_cf(signatures_cf, (block_count - 1).to_le_bytes())
                    .map_err(|e| anyhow!("Failed to delete signature: {}", e))?;
            }
        }
        Ok(Some(block_count - 1))
    }

    /// Get the total number of blocks stored in the blockchain
    ///
    /// # Returns
    /// The count of blocks in the database
    pub fn block_count(&self) -> Result<u64> {
        let blocks_cf = self
            .db
            .cf_handle("blocks")
            .ok_or_else(|| anyhow!("Failed to get blocks column family"))?;
        let count = self.db.iterator_cf(blocks_cf, IteratorMode::Start).count() as u64;
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
        let block_count = self.block_count()?;
        if block_count == 0 {
            return Ok(()); // Empty chain is valid
        }
        for (i, block_result) in self.iter().enumerate() {
            let block = block_result?;
            let expected_height = i as u64;
            if block.block_header.height != expected_height {
                return Err(anyhow!(
                    "Block height mismatch at index {}: expected {}, got {}",
                    i,
                    expected_height,
                    block.block_header.height
                ));
            }
            // Validate genesis block
            if expected_height == 0 {
                if block.block_header.parent_hash != [0u8; BLOCK_HASH_SIZE] {
                    return Err(anyhow!("Genesis block has non-zero parent hash"));
                }
            } else {
                // Validate parent linkage
                let parent_block = self.get_block_by_height(expected_height - 1)?;
                if block.block_header.parent_hash != parent_block.block_hash {
                    return Err(anyhow!(
                        "Block at height {} has invalid parent hash",
                        expected_height
                    ));
                }
            }
            // Validate block hash
            let computed_hash =
                openssl::hash::hash(MessageDigest::sha512(), &block.block_header.bytes())?;
            if computed_hash.as_ref() != block.block_hash {
                return Err(anyhow!(
                    "Block at height {} has invalid hash",
                    expected_height
                ));
            }
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
        let blocks_cf = self.db.cf_handle("blocks").expect("blocks CF not found");
        let iter = self.db.iterator_cf(blocks_cf, IteratorMode::Start);
        BlockIterator {
            blockchain: self,
            iter,
        }
    }
}

/// Iterator over blocks in the blockchain, ordered by height
///
/// This iterator uses RocksDB's native `DBIterator` for efficient sequential access
/// over the "blocks" column family. Blocks are automatically decrypted as they are
/// yielded in ascending height order (0, 1, 2, ...).
pub struct BlockIterator<'a> {
    /// Reference to the blockchain for decryption
    blockchain: &'a BlockChain,
    /// RocksDB iterator over the blocks column family
    iter: rocksdb::DBIteratorWithThreadMode<'a, DB>,
}

impl<'a> Iterator for BlockIterator<'a> {
    type Item = Result<Block>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter.next() {
            Some(Ok((height_bytes, block_bytes))) => {
                // Extract height from key
                let mut height_arr = [0u8; 8];
                if let Some(slice) = height_bytes.get(..BLOCK_HEIGHT_SIZE) {
                    height_arr.copy_from_slice(slice);
                } else {
                    return Some(Err(anyhow!("Invalid height key in database")));
                }
                let height = u64::from_le_bytes(height_arr);
                // Deserialize block and decrypt data
                let block = (|| -> Result<Block> {
                    let stored_height = u64::from_le_bytes(
                        block_bytes
                            .get(0..BLOCK_HEIGHT_SIZE)
                            .and_then(|s| s.try_into().ok())
                            .ok_or_else(|| anyhow!("Failed to read height from block"))?,
                    );
                    if height != stored_height {
                        return Err(anyhow!(
                            "Block height mismatch: expected {}, got {}",
                            height,
                            stored_height
                        ));
                    }
                    let mut block = Block::from_bytes(&block_bytes)?;
                    block.block_data = self.blockchain.decrypt_block_data(&block.block_data)?;
                    Ok(block)
                })();

                Some(block)
            }
            Some(Err(e)) => Some(Err(anyhow!("RocksDB iterator error: {}", e))),
            None => None,
        }
    }
}
