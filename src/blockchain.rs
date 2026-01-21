use crate::block::{BLOCK_HASH_SIZE, BLOCK_HEIGHT_SIZE, Block};
use crate::db_model::RocksDbModel;
use anyhow::{Result, anyhow};
use openssl::hash::MessageDigest;
use rocksdb::{IteratorMode, SingleThreaded};
use std::path::PathBuf;

/// Maximum block size in bytes (100 MB)
pub const MAX_BLOCK_SIZE: usize = 100 * 1024 * 1024;

pub struct BlockChain<Mode> {
    mode: Mode,
}

pub struct ReadOnly {
    db: rocksdb::DBWithThreadMode<SingleThreaded>,
}

pub struct ReadWrite {
    db: rocksdb::DBWithThreadMode<SingleThreaded>,
}

impl BlockChain<ReadOnly> {
    pub fn open_read_only(db_path: PathBuf) -> Result<Self> {
        let db = RocksDbModel::read_only(db_path.clone())
            .with_column_family("blocks")
            .with_column_family("signatures")
            .with_column_family("validation_cache")
            .open()
            .map_err(|e| anyhow!("Failed to open RocksDB in read-only mode: {}", e))?;
        Ok(Self {
            mode: ReadOnly { db },
        })
    }
    pub fn block_count(&self) -> Result<u64> {
        let blocks_cf = self
            .mode
            .db
            .cf_handle("blocks")
            .ok_or_else(|| anyhow!("Failed to get blocks column family"))?;
        let count = self
            .mode
            .db
            .iterator_cf(blocks_cf, IteratorMode::Start)
            .count() as u64;
        Ok(count)
    }
    pub fn get_block_by_height(&self, height: u64) -> Result<Block> {
        let block = (|| -> Result<Block> {
            let blocks_cf = self
                .mode
                .db
                .cf_handle("blocks")
                .ok_or_else(|| anyhow!("Failed to get blocks column family"))?;
            let block_bytes = self
                .mode
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
            let block = Block::from_bytes(&block_bytes)?;
            Ok(block)
        })()?;
        Ok(block)
    }

    pub fn get_signature_by_height(&self, height: u64) -> Result<Vec<u8>> {
        let signatures_cf = self
            .mode
            .db
            .cf_handle("signatures")
            .ok_or_else(|| anyhow!("Failed to get signatures column family"))?;
        let signature = self
            .mode
            .db
            .get_cf(signatures_cf, height.to_le_bytes())
            .map_err(|e| anyhow!("Failed to get signature by height: {}", e))?
            .ok_or_else(|| anyhow!("No signature found at height {}", height))?;
        Ok(signature)
    }

    /// Validate the entire blockchain from genesis to tip
    ///
    /// Performs full validation checking:
    /// - Parent hash chain integrity
    /// - Block hash correctness
    /// - Height gaps
    /// - Timestamp consistency
    /// - Signature presence (if stored)
    ///
    /// This is an expensive O(n) operation. Consider using `validate_incremental()` instead.
    pub fn validate_full(&self) -> Result<()> {
        let block_count = self.block_count()?;
        if block_count == 0 {
            return Ok(()); // Empty chain is valid
        }

        // Check for height gaps by attempting to retrieve all blocks sequentially
        for i in 0..block_count {
            let block = self.get_block_by_height(i).map_err(|e| {
                anyhow!(
                    "Height gap detected: block at height {} is missing or corrupted: {}",
                    i,
                    e
                )
            })?;

            let expected_height = i;
            if block.height() != expected_height {
                return Err(anyhow!(
                    "Block height mismatch at index {}: expected {}, got {}",
                    i,
                    expected_height,
                    block.height()
                ));
            }

            // Validate genesis block
            if expected_height == 0 {
                if block.parent_hash() != [0u8; BLOCK_HASH_SIZE] {
                    return Err(anyhow!("Genesis block has non-zero parent hash"));
                }
                // Genesis block timestamp should be reasonable (not in far future)
                let now = std::time::SystemTime::now();
                let future_threshold = now + std::time::Duration::from_secs(3600); // 1 hour tolerance
                if block.timestamp() > future_threshold {
                    return Err(anyhow!("Genesis block timestamp is too far in the future"));
                }
            } else {
                // Validate parent linkage
                let parent_block = self.get_block_by_height(expected_height - 1)?;
                if block.parent_hash() != parent_block.block_hash() {
                    return Err(anyhow!(
                        "Block at height {} has invalid parent hash",
                        expected_height
                    ));
                }

                // Validate timestamp progression - block timestamp must be >= parent timestamp
                if block.timestamp() < parent_block.timestamp() {
                    return Err(anyhow!(
                        "Block at height {} has timestamp before parent block (block: {:?}, parent: {:?})",
                        expected_height,
                        block.timestamp(),
                        parent_block.timestamp()
                    ));
                }

                // Validate timestamp is not too far in the future
                let now = std::time::SystemTime::now();
                let future_threshold = now + std::time::Duration::from_secs(3600); // 1 hour tolerance
                if block.timestamp() > future_threshold {
                    return Err(anyhow!(
                        "Block at height {} has timestamp too far in the future",
                        expected_height
                    ));
                }
            }

            // Validate block hash
            let computed_hash = (|| -> Result<openssl::hash::DigestBytes> {
                let mut hashing_bytes = block.header_bytes();
                hashing_bytes.extend_from_slice(&block.block_data());
                Ok(openssl::hash::hash(
                    MessageDigest::sha512(),
                    &hashing_bytes,
                )?)
            })()?;
            if computed_hash.as_ref() != block.block_hash() {
                return Err(anyhow!(
                    "Block at height {} has invalid hash",
                    expected_height
                ));
            }

            // Validate signature if present
            match self.get_signature_by_height(expected_height) {
                Ok(signature) => {
                    if signature.is_empty() {
                        return Err(anyhow!(
                            "Block at height {} has empty signature",
                            expected_height
                        ));
                    }
                    // Note: Actual cryptographic signature verification requires
                    // application-specific public key. Here we only verify presence.
                    // Applications should provide their own signature verification
                    // using the stored signature and their public key infrastructure.
                }
                Err(_) => {
                    // Signature is optional - no error if not present
                }
            }
        }
        Ok(())
    }

    /// Validate only blocks added since last validation (incremental)
    ///
    /// Uses a validation cache to track the last validated height.
    /// Only validates blocks from (last_validated_height + 1) to current tip.
    /// Much faster than `validate_full()` for chains that grow over time.
    ///
    /// Returns the height up to which validation succeeded.
    pub fn validate_incremental(&self) -> Result<u64> {
        let block_count = self.block_count()?;
        if block_count == 0 {
            return Ok(0); // Empty chain, nothing to validate
        }

        // Get last validated height from cache
        let validation_cache_cf = self
            .mode
            .db
            .cf_handle("validation_cache")
            .ok_or_else(|| anyhow!("Failed to get validation_cache column family"))?;

        let last_validated = self
            .mode
            .db
            .get_cf(validation_cache_cf, b"last_validated_height")
            .map_err(|e| anyhow!("Failed to read validation cache: {}", e))?
            .and_then(|bytes| {
                if bytes.len() == 8 {
                    Some(u64::from_le_bytes(bytes.try_into().ok()?))
                } else {
                    None
                }
            })
            .unwrap_or(0);

        // If already fully validated, nothing to do
        if last_validated >= block_count - 1 {
            return Ok(last_validated);
        }

        // Validate from (last_validated + 1) to (block_count - 1)
        let start_height = if last_validated == 0 {
            0
        } else {
            last_validated + 1
        };

        for i in start_height..block_count {
            let block = self.get_block_by_height(i).map_err(|e| {
                anyhow!(
                    "Height gap detected: block at height {} is missing or corrupted: {}",
                    i,
                    e
                )
            })?;

            let expected_height = i;
            if block.height() != expected_height {
                return Err(anyhow!(
                    "Block height mismatch at index {}: expected {}, got {}",
                    i,
                    expected_height,
                    block.height()
                ));
            }

            // Validate genesis block
            if expected_height == 0 {
                if block.parent_hash() != [0u8; BLOCK_HASH_SIZE] {
                    return Err(anyhow!("Genesis block has non-zero parent hash"));
                }
                let now = std::time::SystemTime::now();
                let future_threshold = now + std::time::Duration::from_secs(3600);
                if block.timestamp() > future_threshold {
                    return Err(anyhow!("Genesis block timestamp is too far in the future"));
                }
            } else {
                // Validate parent linkage
                let parent_block = self.get_block_by_height(expected_height - 1)?;
                if block.parent_hash() != parent_block.block_hash() {
                    return Err(anyhow!(
                        "Block at height {} has invalid parent hash",
                        expected_height
                    ));
                }

                // Validate timestamp progression
                if block.timestamp() < parent_block.timestamp() {
                    return Err(anyhow!(
                        "Block at height {} has timestamp before parent block (block: {:?}, parent: {:?})",
                        expected_height,
                        block.timestamp(),
                        parent_block.timestamp()
                    ));
                }

                let now = std::time::SystemTime::now();
                let future_threshold = now + std::time::Duration::from_secs(3600);
                if block.timestamp() > future_threshold {
                    return Err(anyhow!(
                        "Block at height {} has timestamp too far in the future",
                        expected_height
                    ));
                }
            }

            // Validate block hash
            let computed_hash = (|| -> Result<openssl::hash::DigestBytes> {
                let mut hashing_bytes = block.header_bytes();
                hashing_bytes.extend_from_slice(&block.block_data());
                Ok(openssl::hash::hash(
                    MessageDigest::sha512(),
                    &hashing_bytes,
                )?)
            })()?;
            if computed_hash.as_ref() != block.block_hash() {
                return Err(anyhow!(
                    "Block at height {} has invalid hash",
                    expected_height
                ));
            }

            // Validate signature if present
            let signatures_cf = self
                .mode
                .db
                .cf_handle("signatures")
                .ok_or_else(|| anyhow!("Failed to get signatures column family"))?;

            match self
                .mode
                .db
                .get_cf(signatures_cf, expected_height.to_le_bytes())
                .map_err(|e| anyhow!("Failed to get signature by height: {}", e))?
            {
                Some(signature) => {
                    if signature.is_empty() {
                        return Err(anyhow!(
                            "Block at height {} has empty signature",
                            expected_height
                        ));
                    }
                }
                None => {
                    // Signature is optional
                }
            }
        }

        // Update validation cache with new height (read-only can't write, so skip)
        // Note: This is read-only mode, cache update happens in ReadWrite mode
        Ok(block_count - 1)
    }

    /// Convenience method that calls validate_incremental()
    ///
    /// For backward compatibility. Use `validate_full()` for complete validation
    /// or `validate_incremental()` for faster incremental validation.
    pub fn validate(&self) -> Result<()> {
        self.validate_incremental()?;
        Ok(())
    }

    /// Returns an iterator over all blocks in the blockchain by height
    pub fn iter(&self) -> Result<BlockIterator<'_, ReadOnly>> {
        let count = self.block_count()?;
        Ok(BlockIterator {
            blockchain: self,
            current_height: 0,
            max_height: count,
        })
    }
}

/// Iterator over blocks in a blockchain
pub struct BlockIterator<'a, M> {
    blockchain: &'a BlockChain<M>,
    current_height: u64,
    max_height: u64,
}

impl<'a> Iterator for BlockIterator<'a, ReadOnly> {
    type Item = Result<Block>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_height >= self.max_height {
            return None;
        }
        let result = self.blockchain.get_block_by_height(self.current_height);
        self.current_height += 1;
        Some(result)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.max_height - self.current_height) as usize;
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for BlockIterator<'a, ReadOnly> {
    fn len(&self) -> usize {
        (self.max_height - self.current_height) as usize
    }
}

impl BlockChain<ReadWrite> {
    pub fn open_read_write(db_path: PathBuf) -> Result<Self> {
        let db = RocksDbModel::new(db_path.clone())
            .with_column_family("blocks")
            .with_column_family("signatures")
            .with_column_family("validation_cache")
            .open()
            .map_err(|e| anyhow!("Failed to open RocksDB in read-write mode: {}", e))?;
        Ok(Self {
            mode: ReadWrite { db },
        })
    }

    pub fn block_count(&self) -> Result<u64> {
        let blocks_cf = self
            .mode
            .db
            .cf_handle("blocks")
            .ok_or_else(|| anyhow!("Failed to get blocks column family"))?;
        let count = self
            .mode
            .db
            .iterator_cf(blocks_cf, IteratorMode::Start)
            .count() as u64;
        Ok(count)
    }

    pub fn get_block_by_height(&self, height: u64) -> Result<Block> {
        let block = (|| -> Result<Block> {
            let blocks_cf = self
                .mode
                .db
                .cf_handle("blocks")
                .ok_or_else(|| anyhow!("Failed to get blocks column family"))?;
            let block_bytes = self
                .mode
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
            let block = Block::from_bytes(&block_bytes)?;
            Ok(block)
        })()?;
        Ok(block)
    }

    pub fn put_block(&self, block_data: Vec<u8>) -> Result<u64> {
        // Check block size limit
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
            // Get the previous block which is 1 less than block count
            let parent_block = self.get_block_by_height(block_count - 1)?;
            let parent_hash = parent_block.block_hash();
            Block::new_regular_block(block_count, parent_hash, block_data)?
        };
        let height = block.height();
        // Store block by height
        let blocks_cf = self
            .mode
            .db
            .cf_handle("blocks")
            .ok_or_else(|| anyhow!("Failed to get blocks column family"))?;
        self.mode
            .db
            .put_cf(blocks_cf, height.to_le_bytes(), block.bytes())
            .map_err(|e| anyhow!("Failed to insert block: {}", e))?;

        // Flush to ensure durability
        self.mode
            .db
            .flush()
            .map_err(|e| anyhow!("Failed to flush database: {}", e))?;

        // Auto-validate the newly inserted block incrementally
        let validated_height = self.validate_incremental()?;

        // Update validation cache
        let validation_cache_cf = self
            .mode
            .db
            .cf_handle("validation_cache")
            .ok_or_else(|| anyhow!("Failed to get validation_cache column family"))?;

        self.mode
            .db
            .put_cf(
                validation_cache_cf,
                b"last_validated_height",
                validated_height.to_le_bytes(),
            )
            .map_err(|e| anyhow!("Failed to update validation cache: {}", e))?;

        Ok(block.height())
    }

    pub fn put_signature(&self, height: u64, signature: Vec<u8>) -> Result<u64> {
        let signatures_cf = self
            .mode
            .db
            .cf_handle("signatures")
            .ok_or_else(|| anyhow!("Failed to get signatures column family"))?;
        self.mode
            .db
            .put_cf(signatures_cf, height.to_le_bytes(), &signature)
            .map_err(|e| anyhow!("Failed to insert signature: {}", e))?;
        Ok(height)
    }

    pub fn delete_last_block(&self) -> Result<Option<u64>> {
        let block_count = self.block_count()?;
        match block_count {
            0 => {
                // Blockchain is empty
                Ok(None)
            }
            _ => {
                // Proceed to delete the latest block
                // Delete block from blocks column family
                let blocks_cf = self
                    .mode
                    .db
                    .cf_handle("blocks")
                    .ok_or_else(|| anyhow!("Failed to get blocks column family"))?;
                self.mode
                    .db
                    .delete_cf(blocks_cf, (block_count - 1).to_le_bytes())
                    .map_err(|e| anyhow!("Failed to delete block: {}", e))?;
                let signatures_cf = self
                    .mode
                    .db
                    .cf_handle("signatures")
                    .ok_or_else(|| anyhow!("Failed to get signatures column family"))?;
                self.mode
                    .db
                    .delete_cf(signatures_cf, (block_count - 1).to_le_bytes())
                    .map_err(|e| anyhow!("Failed to delete signature: {}", e))?;
                Ok(Some(block_count - 1))
            }
        }
    }

    /// Validate the entire blockchain from genesis to tip
    ///
    /// Performs full validation checking:
    /// - Parent hash chain integrity
    /// - Block hash correctness
    /// - Height gaps
    /// - Timestamp consistency
    /// - Signature presence (if stored)
    ///
    /// This is an expensive O(n) operation. Consider using `validate_incremental()` instead.
    pub fn validate_full(&self) -> Result<()> {
        let block_count = self.block_count()?;
        if block_count == 0 {
            return Ok(()); // Empty chain is valid
        }

        // Check for height gaps by attempting to retrieve all blocks sequentially
        for i in 0..block_count {
            let block = self.get_block_by_height(i).map_err(|e| {
                anyhow!(
                    "Height gap detected: block at height {} is missing or corrupted: {}",
                    i,
                    e
                )
            })?;

            let expected_height = i;
            if block.height() != expected_height {
                return Err(anyhow!(
                    "Block height mismatch at index {}: expected {}, got {}",
                    i,
                    expected_height,
                    block.height()
                ));
            }

            // Validate genesis block
            if expected_height == 0 {
                if block.parent_hash() != [0u8; BLOCK_HASH_SIZE] {
                    return Err(anyhow!("Genesis block has non-zero parent hash"));
                }
                // Genesis block timestamp should be reasonable (not in far future)
                let now = std::time::SystemTime::now();
                let future_threshold = now + std::time::Duration::from_secs(3600); // 1 hour tolerance
                if block.timestamp() > future_threshold {
                    return Err(anyhow!("Genesis block timestamp is too far in the future"));
                }
            } else {
                // Validate parent linkage
                let parent_block = self.get_block_by_height(expected_height - 1)?;
                if block.parent_hash() != parent_block.block_hash() {
                    return Err(anyhow!(
                        "Block at height {} has invalid parent hash",
                        expected_height
                    ));
                }

                // Validate timestamp progression - block timestamp must be >= parent timestamp
                if block.timestamp() < parent_block.timestamp() {
                    return Err(anyhow!(
                        "Block at height {} has timestamp before parent block (block: {:?}, parent: {:?})",
                        expected_height,
                        block.timestamp(),
                        parent_block.timestamp()
                    ));
                }

                // Validate timestamp is not too far in the future
                let now = std::time::SystemTime::now();
                let future_threshold = now + std::time::Duration::from_secs(3600); // 1 hour tolerance
                if block.timestamp() > future_threshold {
                    return Err(anyhow!(
                        "Block at height {} has timestamp too far in the future",
                        expected_height
                    ));
                }
            }

            // Validate block hash
            let computed_hash = (|| -> Result<openssl::hash::DigestBytes> {
                let mut hashing_bytes = block.header_bytes();
                hashing_bytes.extend_from_slice(&block.block_data());
                Ok(openssl::hash::hash(
                    MessageDigest::sha512(),
                    &hashing_bytes,
                )?)
            })()?;
            if computed_hash.as_ref() != block.block_hash() {
                return Err(anyhow!(
                    "Block at height {} has invalid hash",
                    expected_height
                ));
            }

            // Validate signature if present
            let signatures_cf = self
                .mode
                .db
                .cf_handle("signatures")
                .ok_or_else(|| anyhow!("Failed to get signatures column family"))?;

            match self
                .mode
                .db
                .get_cf(signatures_cf, expected_height.to_le_bytes())
                .map_err(|e| anyhow!("Failed to get signature by height: {}", e))?
            {
                Some(signature) => {
                    if signature.is_empty() {
                        return Err(anyhow!(
                            "Block at height {} has empty signature",
                            expected_height
                        ));
                    }
                    // Note: Actual cryptographic signature verification requires
                    // application-specific public key. Here we only verify presence.
                    // Applications should provide their own signature verification
                    // using the stored signature and their public key infrastructure.
                }
                None => {
                    // Signature is optional - no error if not present
                }
            }
        }
        Ok(())
    }

    /// Validate only blocks added since last validation (incremental)
    ///
    /// Uses a validation cache to track the last validated height.
    /// Only validates blocks from (last_validated_height + 1) to current tip.
    /// Much faster than `validate_full()` for chains that grow over time.
    /// Updates the validation cache after successful validation.
    ///
    /// Returns the height up to which validation succeeded.
    pub fn validate_incremental(&self) -> Result<u64> {
        let block_count = self.block_count()?;
        if block_count == 0 {
            return Ok(0); // Empty chain, nothing to validate
        }

        // Get last validated height from cache
        let validation_cache_cf = self
            .mode
            .db
            .cf_handle("validation_cache")
            .ok_or_else(|| anyhow!("Failed to get validation_cache column family"))?;

        let last_validated = self
            .mode
            .db
            .get_cf(validation_cache_cf, b"last_validated_height")
            .map_err(|e| anyhow!("Failed to read validation cache: {}", e))?
            .and_then(|bytes| {
                if bytes.len() == 8 {
                    Some(u64::from_le_bytes(bytes.try_into().ok()?))
                } else {
                    None
                }
            })
            .unwrap_or(0);

        // If already fully validated, nothing to do
        if last_validated >= block_count - 1 {
            return Ok(last_validated);
        }

        // Validate from (last_validated + 1) to (block_count - 1)
        let start_height = if last_validated == 0 {
            0
        } else {
            last_validated + 1
        };

        for i in start_height..block_count {
            let block = self.get_block_by_height(i).map_err(|e| {
                anyhow!(
                    "Height gap detected: block at height {} is missing or corrupted: {}",
                    i,
                    e
                )
            })?;

            let expected_height = i;
            if block.height() != expected_height {
                return Err(anyhow!(
                    "Block height mismatch at index {}: expected {}, got {}",
                    i,
                    expected_height,
                    block.height()
                ));
            }

            // Validate genesis block
            if expected_height == 0 {
                if block.parent_hash() != [0u8; BLOCK_HASH_SIZE] {
                    return Err(anyhow!("Genesis block has non-zero parent hash"));
                }
                let now = std::time::SystemTime::now();
                let future_threshold = now + std::time::Duration::from_secs(3600);
                if block.timestamp() > future_threshold {
                    return Err(anyhow!("Genesis block timestamp is too far in the future"));
                }
            } else {
                // Validate parent linkage
                let parent_block = self.get_block_by_height(expected_height - 1)?;
                if block.parent_hash() != parent_block.block_hash() {
                    return Err(anyhow!(
                        "Block at height {} has invalid parent hash",
                        expected_height
                    ));
                }

                // Validate timestamp progression
                if block.timestamp() < parent_block.timestamp() {
                    return Err(anyhow!(
                        "Block at height {} has timestamp before parent block (block: {:?}, parent: {:?})",
                        expected_height,
                        block.timestamp(),
                        parent_block.timestamp()
                    ));
                }

                let now = std::time::SystemTime::now();
                let future_threshold = now + std::time::Duration::from_secs(3600);
                if block.timestamp() > future_threshold {
                    return Err(anyhow!(
                        "Block at height {} has timestamp too far in the future",
                        expected_height
                    ));
                }
            }

            // Validate block hash
            let computed_hash = (|| -> Result<openssl::hash::DigestBytes> {
                let mut hashing_bytes = block.header_bytes();
                hashing_bytes.extend_from_slice(&block.block_data());
                Ok(openssl::hash::hash(
                    MessageDigest::sha512(),
                    &hashing_bytes,
                )?)
            })()?;
            if computed_hash.as_ref() != block.block_hash() {
                return Err(anyhow!(
                    "Block at height {} has invalid hash",
                    expected_height
                ));
            }

            // Validate signature if present
            let signatures_cf = self
                .mode
                .db
                .cf_handle("signatures")
                .ok_or_else(|| anyhow!("Failed to get signatures column family"))?;

            match self
                .mode
                .db
                .get_cf(signatures_cf, expected_height.to_le_bytes())
                .map_err(|e| anyhow!("Failed to get signature by height: {}", e))?
            {
                Some(signature) => {
                    if signature.is_empty() {
                        return Err(anyhow!(
                            "Block at height {} has empty signature",
                            expected_height
                        ));
                    }
                }
                None => {
                    // Signature is optional
                }
            }
        }

        // Successfully validated up to block_count - 1
        Ok(block_count - 1)
    }

    /// Convenience method that calls validate_incremental()
    ///
    /// For backward compatibility. Use `validate_full()` for complete validation
    /// or `validate_incremental()` for faster incremental validation.
    pub fn validate(&self) -> Result<()> {
        self.validate_incremental()?;
        Ok(())
    }

    /// Returns an iterator over all blocks in the blockchain by height
    pub fn iter(&self) -> Result<BlockIterator<'_, ReadWrite>> {
        let count = self.block_count()?;
        Ok(BlockIterator {
            blockchain: self,
            current_height: 0,
            max_height: count,
        })
    }
}

impl<'a> Iterator for BlockIterator<'a, ReadWrite> {
    type Item = Result<Block>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_height >= self.max_height {
            return None;
        }
        let result = self.blockchain.get_block_by_height(self.current_height);
        self.current_height += 1;
        Some(result)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.max_height - self.current_height) as usize;
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for BlockIterator<'a, ReadWrite> {
    fn len(&self) -> usize {
        (self.max_height - self.current_height) as usize
    }
}

pub fn open_read_only_chain(path: PathBuf) -> Result<BlockChain<ReadOnly>> {
    BlockChain::<ReadOnly>::open_read_only(path)
}

pub fn open_read_write_chain(path: PathBuf) -> Result<BlockChain<ReadWrite>> {
    BlockChain::<ReadWrite>::open_read_write(path)
}
