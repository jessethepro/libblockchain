use crate::block::{BLOCK_HASH_SIZE, BLOCK_HEIGHT_SIZE, Block};
use crate::db_model::RocksDbModel;
use anyhow::{Result, anyhow};
use openssl::hash::MessageDigest;
use rocksdb::{DB, IteratorMode};
use std::sync::Arc;

pub const AES_KEY_LEN_SIZE: usize = 4; // u32 for AES key length
pub const AES_GCM_256_KEY_SIZE: usize = 32; // 256 bits
pub const AES_GCM_NONCE_SIZE: usize = 12; // 96 bits
pub const AES_GCM_TAG_SIZE: usize = 16; // 128 bits
pub const DATA_LEN_SIZE: usize = 4; // u32 for block length

pub struct BlockChain {
    /// Path to RocksDB database
    db_path: std::path::PathBuf,
}

impl BlockChain {
    pub fn new(path: std::path::PathBuf) -> Result<Self> {
        Ok(Self { db_path: path })
    }

    pub fn put_block(&self, block_data: Vec<u8>) -> Result<u64> {
        let db = RocksDbModel::new(&self.db_path)
            .with_column_family("blocks")
            .with_column_family("signatures")
            .open()
            .map_err(|e| anyhow!("Failed to open RocksDB: {}", e))?;
        let block_count = self.block_count()?;
        let block = if block_count == 0 {
            Block::new_genesis_block(block_data)
        } else {
            // Get the previous block which is 1 less than block count
            let parent_block = self.get_block_by_height(block_count - 1)?;
            let parent_hash = parent_block.block_hash();
            Block::new_regular_block(block_count, parent_hash, block_data)
        };
        let height = block.height();
        // Store block by height
        let blocks_cf = db
            .cf_handle("blocks")
            .ok_or_else(|| anyhow!("Failed to get blocks column family"))?;
        db.put_cf(blocks_cf, height.to_le_bytes(), block.bytes())
            .map_err(|e| anyhow!("Failed to insert block: {}", e))?;

        // Flush to ensure durability
        db.flush()
            .map_err(|e| anyhow!("Failed to flush database: {}", e))?;

        Ok(block.height())
    }

    pub fn put_signature(&self, height: u64, signature: Vec<u8>) -> Result<u64> {
        let db = RocksDbModel::new(&self.db_path)
            .with_column_family("blocks")
            .with_column_family("signatures")
            .open()
            .map_err(|e| anyhow!("Failed to open RocksDB: {}", e))?;
        let signatures_cf = db
            .cf_handle("signatures")
            .ok_or_else(|| anyhow!("Failed to get signatures column family"))?;
        db.put_cf(signatures_cf, height.to_le_bytes(), &signature)
            .map_err(|e| anyhow!("Failed to insert signature: {}", e))?;
        Ok(height)
    }

    pub fn get_block_by_height(&self, height: u64) -> Result<Block> {
        let db = RocksDbModel::read_only(&self.db_path)
            .with_column_family("blocks")
            .with_column_family("signatures")
            .open()
            .map_err(|e| anyhow!("Failed to open RocksDB: {}", e))?;
        let blocks_cf = db
            .cf_handle("blocks")
            .ok_or_else(|| anyhow!("Failed to get blocks column family"))?;
        let block = (|| -> Result<Block> {
            let block_bytes = db
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
        let db = RocksDbModel::read_only(&self.db_path)
            .with_column_family("blocks")
            .with_column_family("signatures")
            .open()
            .map_err(|e| anyhow!("Failed to open RocksDB: {}", e))?;
        let signatures_cf = db
            .cf_handle("signatures")
            .ok_or_else(|| anyhow!("Failed to get signatures column family"))?;
        let signature = db
            .get_cf(signatures_cf, height.to_le_bytes())
            .map_err(|e| anyhow!("Failed to get signature by height: {}", e))?
            .ok_or_else(|| anyhow!("No signature found at height {}", height))?;
        Ok(signature)
    }

    pub fn get_max_height(&self) -> Result<u64> {
        let count = self.block_count()?;
        if count == 0 { Ok(0) } else { Ok(count - 1) }
    }

    pub fn delete_latest_block(&self) -> Result<Option<u64>> {
        let db = RocksDbModel::new(&self.db_path)
            .with_column_family("blocks")
            .with_column_family("signatures")
            .open()
            .map_err(|e| anyhow!("Failed to open RocksDB: {}", e))?;
        let block_count = self.block_count()?;
        match block_count {
            0 => {
                // Blockchain is empty
                return Ok(None);
            }
            _ => {
                // Proceed to delete the latest block
                // Delete block from blocks column family
                let blocks_cf = db
                    .cf_handle("blocks")
                    .ok_or_else(|| anyhow!("Failed to get blocks column family"))?;
                db.delete_cf(blocks_cf, (block_count - 1).to_le_bytes())
                    .map_err(|e| anyhow!("Failed to delete block: {}", e))?;
                let signatures_cf = db
                    .cf_handle("signatures")
                    .ok_or_else(|| anyhow!("Failed to get signatures column family"))?;
                db.delete_cf(signatures_cf, (block_count - 1).to_le_bytes())
                    .map_err(|e| anyhow!("Failed to delete signature: {}", e))?;
                Ok(Some(block_count - 1))
            }
        }
    }

    pub fn block_count(&self) -> Result<u64> {
        let db = RocksDbModel::read_only(&self.db_path)
            .with_column_family("blocks")
            .with_column_family("signatures")
            .open()
            .map_err(|e| anyhow!("Failed to open RocksDB: {}", e))?;
        let blocks_cf = db
            .cf_handle("blocks")
            .ok_or_else(|| anyhow!("Failed to get blocks column family"))?;
        let count = db.iterator_cf(blocks_cf, IteratorMode::Start).count() as u64;
        Ok(count)
    }

    pub fn validate(&self) -> Result<()> {
        let block_count = self.block_count()?;
        if block_count == 0 {
            return Ok(()); // Empty chain is valid
        }
        for (i, block_result) in self.iter().enumerate() {
            let block = block_result?;
            let expected_height = i as u64;
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
            } else {
                // Validate parent linkage
                let parent_block = self.get_block_by_height(expected_height - 1)?;
                if block.parent_hash() != parent_block.block_hash() {
                    return Err(anyhow!(
                        "Block at height {} has invalid parent hash",
                        expected_height
                    ));
                }
            }
            // Validate block hash
            let computed_hash = (|| -> Result<openssl::hash::DigestBytes> {
                let mut hashing_bytes = Vec::from(block.block_header.bytes());
                hashing_bytes.extend_from_slice(&block.block_data);
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
        }
        Ok(())
    }

    pub fn iter(&self) -> BlockIterator<'_> {
        let db = Arc::new(
            RocksDbModel::read_only(&self.db_path)
                .with_column_family("blocks")
                .with_column_family("signatures")
                .open()
                .expect("Failed to open RocksDB for iteration"),
        );
        let blocks_cf = db.cf_handle("blocks").expect("blocks CF not found");
        let db_clone = Arc::clone(&db);
        // SAFETY: We extend the lifetime by keeping the Arc alive in the struct
        let iter = unsafe {
            std::mem::transmute::<rocksdb::DBIterator<'_>, rocksdb::DBIterator<'_>>(
                db.iterator_cf(blocks_cf, IteratorMode::Start),
            )
        };
        BlockIterator {
            _db: db_clone,
            iter,
        }
    }
}

pub struct BlockIterator<'a> {
    /// Database handle that owns the data
    _db: Arc<DB>,
    /// RocksDB iterator over the blocks column family
    iter: rocksdb::DBIterator<'a>,
}

impl<'a> Iterator for BlockIterator<'a> {
    type Item = Result<Block>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter.next() {
            Some(Ok((height_bytes, block_bytes))) => {
                // Extract height from key
                let mut height_arr = [0u8; 8];
                if let Some(slice) = height_bytes.as_ref().get(..BLOCK_HEIGHT_SIZE) {
                    height_arr.copy_from_slice(slice);
                } else {
                    return Some(Err(anyhow!("Invalid height key in database")));
                }
                let height = u64::from_le_bytes(height_arr);
                // Deserialize block and decrypt data
                let block = (|| -> Result<Block> {
                    let stored_height = u64::from_le_bytes(
                        block_bytes
                            .as_ref()
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
                    let block = Block::from_bytes(&block_bytes)?;
                    Ok(block)
                })();

                Some(block)
            }
            Some(Err(e)) => Some(Err(anyhow!("RocksDB iterator error: {}", e))),
            None => None,
        }
    }
}
