use crate::block::{BLOCK_HASH_SIZE, BLOCK_HEIGHT_SIZE, Block};
use crate::db_model::RocksDbModel;
use anyhow::{Result, anyhow};
use openssl::hash::MessageDigest;
use rocksdb::{BoundColumnFamily, IteratorMode, MultiThreaded};
use std::sync::Arc;

/// Maximum block size in bytes (100 MB)
pub const MAX_BLOCK_SIZE: usize = 100 * 1024 * 1024;

/// RocksDB-backed blockchain handle.
///
/// `BlockChain` exposes a single cloneable read/write API. Internally it shares a
/// `DBWithThreadMode<MultiThreaded>` through `Arc`, so the same open handle can be
/// moved across threads cheaply.
///
/// Blocks are keyed by height in the `blocks` column family and signatures are keyed
/// by height in the `signatures` column family. A third `validation_cache` column
/// family stores the last incrementally validated height.
#[derive(Clone)]
pub struct BlockChain {
    db: Arc<rocksdb::DBWithThreadMode<MultiThreaded>>,
}

impl BlockChain {
    /// Open or create a blockchain database at `db_path`.
    ///
    /// This configures the `blocks`, `signatures`, and `validation_cache` column
    /// families and opens RocksDB in multi-threaded mode.
    pub fn open(db_path: &str) -> Result<Self> {
        let db = RocksDbModel::new(db_path)
            .with_column_family("blocks")
            .with_column_family("signatures")
            .with_column_family("validation_cache")
            .open_multi_threaded()
            .map_err(|e| anyhow!("Failed to open RocksDB in read-write mode: {}", e))?;
        Ok(Self { db: Arc::new(db) })
    }

    fn blocks_cf(&self) -> Result<Arc<BoundColumnFamily<'_>>> {
        self.db
            .cf_handle("blocks")
            .ok_or_else(|| anyhow!("Failed to get blocks column family"))
    }

    fn signatures_cf(&self) -> Result<Arc<BoundColumnFamily<'_>>> {
        self.db
            .cf_handle("signatures")
            .ok_or_else(|| anyhow!("Failed to get signatures column family"))
    }

    fn validation_cache_cf(&self) -> Result<Arc<BoundColumnFamily<'_>>> {
        self.db
            .cf_handle("validation_cache")
            .ok_or_else(|| anyhow!("Failed to get validation_cache column family"))
    }

    /// Return the number of blocks currently stored in the chain.
    pub fn block_count(&self) -> Result<u64> {
        let blocks_cf = self.blocks_cf()?;
        Ok(self.db.iterator_cf(&blocks_cf, IteratorMode::Start).count() as u64)
    }

    /// Retrieve a block and its signature by height.
    ///
    /// The return value is a pair of results so callers can distinguish block read
    /// failures from signature lookup failures without losing either error.
    /// Missing signatures are returned as an empty vector in the signature result.
    pub fn get_block_by_height(&self, height: u64) -> (Result<Block>, Result<Vec<u8>>) {
        let block = (|| -> Result<Block> {
            let blocks_cf = self.blocks_cf()?;
            let block_bytes = self
                .db
                .get_cf(&blocks_cf, height.to_le_bytes())
                .map_err(|e| anyhow!("Failed to get block by height: {}", e))?
                .ok_or_else(|| anyhow!("No block found at height {}", height))?;
            let stored_height = u64::from_le_bytes(
                block_bytes
                    .get(0..BLOCK_HEIGHT_SIZE)
                    .and_then(|slice| slice.try_into().ok())
                    .ok_or_else(|| anyhow!("Failed to read height from stored block"))?,
            );
            if height != stored_height {
                return Err(anyhow!(
                    "Block height mismatch: expected {}, got {}",
                    height,
                    stored_height
                ));
            }
            Block::from_bytes(&block_bytes)
        })();

        let signature = (|| -> Result<Vec<u8>> {
            let signatures_cf = self.signatures_cf()?;
            match self
                .db
                .get_cf(&signatures_cf, height.to_le_bytes())
                .map_err(|e| anyhow!("Failed to get signature by height: {}", e))?
            {
                Some(sig) => Ok(sig),
                None => Ok(vec![]),
            }
        })();

        (block, signature)
    }

    /// Retrieve only the signature stored for `height`.
    pub fn get_signature_by_height(&self, height: u64) -> Result<Vec<u8>> {
        let signatures_cf = self.signatures_cf()?;
        self.db
            .get_cf(&signatures_cf, height.to_le_bytes())
            .map_err(|e| anyhow!("Failed to get signature by height: {}", e))?
            .ok_or_else(|| anyhow!("No signature found at height {}", height))
    }

    /// Validate the entire blockchain from genesis to tip.
    ///
    /// This performs a full scan of the chain and checks:
    /// - sequential heights
    /// - genesis parent hash invariants
    /// - parent hash linkage
    /// - timestamp ordering and basic future skew limits
    /// - SHA-512 block hash correctness
    /// - signature presence for each block
    pub fn validate_full(&self) -> Result<()> {
        let block_count = self.block_count()?;
        if block_count == 0 {
            return Ok(());
        }

        for height in 0..block_count {
            let (block, signature) = match self.get_block_by_height(height) {
                (Ok(block), Ok(signature)) => (block, signature),
                (Err(e), _) | (_, Err(e)) => {
                    return Err(anyhow!(
                        "Height gap detected: block at height {} is missing or corrupted: {}",
                        height,
                        e
                    ));
                }
            };

            if block.height() != height {
                return Err(anyhow!(
                    "Block height mismatch at index {}: expected {}, got {}",
                    height,
                    height,
                    block.height()
                ));
            }

            if height == 0 {
                if block.parent_hash() != [0u8; BLOCK_HASH_SIZE] {
                    return Err(anyhow!("Genesis block has non-zero parent hash"));
                }
                let now = std::time::SystemTime::now();
                let future_threshold = now + std::time::Duration::from_secs(3600);
                if block.timestamp() > future_threshold {
                    return Err(anyhow!("Genesis block timestamp is too far in the future"));
                }
            } else {
                let parent_block = match self.get_block_by_height(height - 1) {
                    (Ok(block), Ok(_)) => block,
                    (Err(e), _) | (_, Err(e)) => {
                        return Err(anyhow!(
                            "Failed to retrieve parent block at height {}: {}",
                            height - 1,
                            e
                        ));
                    }
                };
                if block.parent_hash() != parent_block.block_hash() {
                    return Err(anyhow!(
                        "Block at height {} has invalid parent hash",
                        height
                    ));
                }
                if block.timestamp() < parent_block.timestamp() {
                    return Err(anyhow!(
                        "Block at height {} has timestamp before parent block (block: {:?}, parent: {:?})",
                        height,
                        block.timestamp(),
                        parent_block.timestamp()
                    ));
                }
                let now = std::time::SystemTime::now();
                let future_threshold = now + std::time::Duration::from_secs(3600);
                if block.timestamp() > future_threshold {
                    return Err(anyhow!(
                        "Block at height {} has timestamp too far in the future",
                        height
                    ));
                }
            }

            let computed_hash = {
                let mut hashing_bytes = block.header_bytes();
                hashing_bytes.extend_from_slice(&block.block_data());
                openssl::hash::hash(MessageDigest::sha512(), &hashing_bytes)?
            };
            if computed_hash.as_ref() != block.block_hash() {
                return Err(anyhow!("Block at height {} has invalid hash", height));
            }

            if signature.is_empty() {
                return Err(anyhow!("Block at height {} has empty signature", height));
            }
        }

        Ok(())
    }

    /// Validate only blocks added since the cached validation height.
    ///
    /// The highest validated height is read from the `validation_cache` column family.
    /// This is much cheaper than [`Self::validate_full`] when the chain only grows by a
    /// few blocks between validation runs.
    pub fn validate_incremental(&self) -> Result<u64> {
        let block_count = self.block_count()?;
        if block_count == 0 {
            return Ok(0);
        }

        let validation_cache_cf = self.validation_cache_cf()?;
        let last_validated = self
            .db
            .get_cf(&validation_cache_cf, b"last_validated_height")
            .map_err(|e| anyhow!("Failed to read validation cache: {}", e))?
            .and_then(|bytes| {
                if bytes.len() == 8 {
                    Some(u64::from_le_bytes(bytes.try_into().ok()?))
                } else {
                    None
                }
            })
            .unwrap_or(0);

        if last_validated >= block_count - 1 {
            return Ok(last_validated);
        }

        let start_height = if last_validated == 0 {
            0
        } else {
            last_validated + 1
        };

        for height in start_height..block_count {
            let (block, signature) = match self.get_block_by_height(height) {
                (Ok(block), Ok(signature)) => (block, signature),
                (Err(e), _) | (_, Err(e)) => {
                    return Err(anyhow!(
                        "Height gap detected: block at height {} is missing or corrupted: {}",
                        height,
                        e
                    ));
                }
            };

            if block.height() != height {
                return Err(anyhow!(
                    "Block height mismatch at index {}: expected {}, got {}",
                    height,
                    height,
                    block.height()
                ));
            }

            if height == 0 {
                if block.parent_hash() != [0u8; BLOCK_HASH_SIZE] {
                    return Err(anyhow!("Genesis block has non-zero parent hash"));
                }
                let now = std::time::SystemTime::now();
                let future_threshold = now + std::time::Duration::from_secs(3600);
                if block.timestamp() > future_threshold {
                    return Err(anyhow!("Genesis block timestamp is too far in the future"));
                }
            } else {
                let parent_block = match self.get_block_by_height(height - 1) {
                    (Ok(block), Ok(_)) => block,
                    (Err(e), _) | (_, Err(e)) => {
                        return Err(anyhow!(
                            "Height gap detected: block at height {} is missing or corrupted: {}",
                            height - 1,
                            e
                        ));
                    }
                };
                if block.parent_hash() != parent_block.block_hash() {
                    return Err(anyhow!(
                        "Block at height {} has invalid parent hash",
                        height
                    ));
                }
                if block.timestamp() < parent_block.timestamp() {
                    return Err(anyhow!(
                        "Block at height {} has timestamp before parent block (block: {:?}, parent: {:?})",
                        height,
                        block.timestamp(),
                        parent_block.timestamp()
                    ));
                }
                let now = std::time::SystemTime::now();
                let future_threshold = now + std::time::Duration::from_secs(3600);
                if block.timestamp() > future_threshold {
                    return Err(anyhow!(
                        "Block at height {} has timestamp too far in the future",
                        height
                    ));
                }
            }

            let computed_hash = {
                let mut hashing_bytes = block.header_bytes();
                hashing_bytes.extend_from_slice(&block.block_data());
                openssl::hash::hash(MessageDigest::sha512(), &hashing_bytes)?
            };
            if computed_hash.as_ref() != block.block_hash() {
                return Err(anyhow!("Block at height {} has invalid hash", height));
            }

            if signature.is_empty() {
                return Err(anyhow!("Block at height {} has empty signature", height));
            }
        }

        Ok(block_count - 1)
    }

    /// Convenience wrapper around [`Self::validate_incremental`].
    pub fn validate(&self) -> Result<()> {
        self.validate_incremental()?;
        Ok(())
    }

    /// Append a block and its signature to the chain.
    ///
    /// Heights are assigned automatically. The new block is written together with its
    /// signature, flushed, then validated incrementally. On success, the new height is
    /// returned.
    pub fn put_block(&self, block_data: Vec<u8>, signature: Vec<u8>) -> Result<u64> {
        if block_data.len() > MAX_BLOCK_SIZE {
            return Err(anyhow!(
                "Block data exceeds maximum size: {} bytes (max: {} bytes)",
                block_data.len(),
                MAX_BLOCK_SIZE
            ));
        }

        let block_count = self.block_count()?;
        let block = if block_count == 0 {
            Block::new_genesis_block(block_data)?
        } else {
            let parent_block = match self.get_block_by_height(block_count - 1) {
                (Ok(block), Ok(_)) => block,
                (Err(e), _) | (_, Err(e)) => {
                    return Err(anyhow!(
                        "Failed to retrieve parent block at height {}: {}",
                        block_count - 1,
                        e
                    ));
                }
            };
            Block::new_regular_block(block_count, parent_block.block_hash(), block_data)?
        };

        let height = block.height();
        let blocks_cf = self.blocks_cf()?;
        self.db
            .put_cf(&blocks_cf, height.to_le_bytes(), block.bytes())
            .map_err(|e| anyhow!("Failed to insert block: {}", e))?;

        let signatures_cf = self.signatures_cf()?;
        self.db
            .put_cf(&signatures_cf, height.to_le_bytes(), &signature)
            .map_err(|e| anyhow!("Failed to insert signature: {}", e))?;

        self.db
            .flush()
            .map_err(|e| anyhow!("Failed to flush database: {}", e))?;

        let validated_height = self.validate_incremental()?;
        let validation_cache_cf = self.validation_cache_cf()?;
        self.db
            .put_cf(
                &validation_cache_cf,
                b"last_validated_height",
                validated_height.to_le_bytes(),
            )
            .map_err(|e| anyhow!("Failed to update validation cache: {}", e))?;

        Ok(height)
    }

    /// Store or replace the signature for an existing block height.
    pub fn put_signature(&self, height: u64, signature: Vec<u8>) -> Result<u64> {
        let signatures_cf = self.signatures_cf()?;
        self.db
            .put_cf(&signatures_cf, height.to_le_bytes(), &signature)
            .map_err(|e| anyhow!("Failed to insert signature: {}", e))?;
        Ok(height)
    }

    /// Delete the most recently appended block and its signature.
    ///
    /// Returns `Ok(None)` if the chain is empty.
    pub fn delete_last_block(&self) -> Result<Option<u64>> {
        let block_count = self.block_count()?;
        if block_count == 0 {
            return Ok(None);
        }

        let height = block_count - 1;
        let blocks_cf = self.blocks_cf()?;
        self.db
            .delete_cf(&blocks_cf, height.to_le_bytes())
            .map_err(|e| anyhow!("Failed to delete block: {}", e))?;

        let signatures_cf = self.signatures_cf()?;
        self.db
            .delete_cf(&signatures_cf, height.to_le_bytes())
            .map_err(|e| anyhow!("Failed to delete signature: {}", e))?;

        Ok(Some(height))
    }
}

/// Open or create a blockchain database at `path`.
pub fn open_chain(path: &str) -> Result<BlockChain> {
    BlockChain::open(path)
}
