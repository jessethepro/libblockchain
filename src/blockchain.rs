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
//! # Concurrency
//!
//! The database is Arc-wrapped and thread-safe. RocksDB handles concurrent
//! reads efficiently, while writes are serialized internally.

use crate::block::{BLOCK_HASH_SIZE, BLOCK_HEIGHT_SIZE, BLOCK_UID_SIZE, Block};
use crate::db_model::RocksDbModel;
use anyhow::{Context, Result, anyhow};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Padding;
use openssl::symm::Cipher;
use rocksdb::{DB, IteratorMode};
use secrecy::{ExposeSecret, SecretBox, zeroize::Zeroize};
use std::fmt;
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
/// # Thread Safety
///
/// The `BlockChain` is thread-safe with an Arc-wrapped RocksDB instance.
/// Multiple readers can access blocks concurrently, while RocksDB serializes
/// write operations internally.
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
            .with_column_family("signatures")
            .open()
            .map_err(|e| anyhow!("Failed to open RocksDB: {}", e))?;

        let db = std::sync::Arc::new(db);

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
    /// `Ok([u8; BLOCK_UID_SIZE])` - The UUID of the newly inserted block on success
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
    pub fn put_block(&self, block_data: Vec<u8>) -> Result<[u8; BLOCK_UID_SIZE]> {
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
            .put_cf(blocks_cf, height.to_le_bytes(), &block.bytes())
            .map_err(|e| anyhow!("Failed to insert block: {}", e))?;

        // Flush to ensure durability
        self.db
            .flush()
            .map_err(|e| anyhow!("Failed to flush database: {}", e))?;

        Ok(block.block_header.block_uid)
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
            if height != u64::from_le_bytes(block_bytes[0..BLOCK_HEIGHT_SIZE].try_into().unwrap()) {
                return Err(anyhow!(
                    "Block height mismatch: expected {}, got {}",
                    height,
                    u64::from_le_bytes(block_bytes[0..BLOCK_HEIGHT_SIZE].try_into().unwrap())
                ));
            }
            let mut block = Block::from_bytes(&block_bytes)?;
            block.block_data = self.decrypt_block_data(&block.block_data)?;
            Ok(block)
        })()?;
        Ok(block)
    }

    fn decrypt_block_data(&self, encrypted_block_data: &[u8]) -> Result<Vec<u8>> {
        let mut index = 0;
        let aes_key_len = u32::from_le_bytes(
            // u32 for the length of the encrypted AES key
            encrypted_block_data[index..index + AES_KEY_LEN_SIZE]
                .try_into()
                .unwrap(),
        ) as usize;
        index += AES_KEY_LEN_SIZE;
        let encrypted_aes_key = &encrypted_block_data[index..index + aes_key_len];
        index += aes_key_len;
        let nonce = &encrypted_block_data[index..index + AES_GCM_NONCE_SIZE];
        index += AES_GCM_NONCE_SIZE;
        let tag = &encrypted_block_data[index..index + AES_GCM_TAG_SIZE];
        index += AES_GCM_TAG_SIZE;
        let data_len = u32::from_le_bytes(
            encrypted_block_data[index..index + DATA_LEN_SIZE]
                .try_into()
                .unwrap(),
        ) as usize;
        index += DATA_LEN_SIZE;
        let data_bytes = &encrypted_block_data[index..index + data_len];
        let decrypted_data = {
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
                data_bytes,
                tag,
            )
            .map_err(|e| anyhow!("AES-GCM decryption failed: {}", e))?;
            decrypted_data
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
                height_arr.copy_from_slice(&height_bytes[..BLOCK_HEIGHT_SIZE]);
                let height = u64::from_le_bytes(height_arr);
                // Deserialize block and decrypt data
                let block = (|| -> Result<Block> {
                    if height
                        != u64::from_le_bytes(block_bytes[0..BLOCK_HEIGHT_SIZE].try_into().unwrap())
                    {
                        return Err(anyhow!(
                            "Block height mismatch: expected {}, got {}",
                            height,
                            u64::from_le_bytes(
                                block_bytes[0..BLOCK_HEIGHT_SIZE].try_into().unwrap()
                            )
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
