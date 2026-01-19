use crate::block::{BLOCK_HASH_SIZE, BLOCK_HEIGHT_SIZE, Block};
use crate::db_model::RocksDbModel;
use anyhow::{Result, anyhow};
use openssl::hash::MessageDigest;
use rocksdb::{IteratorMode, SingleThreaded};
use std::path::PathBuf;

pub const AES_KEY_LEN_SIZE: usize = 4; // u32 for AES key length
pub const AES_GCM_256_KEY_SIZE: usize = 32; // 256 bits
pub const AES_GCM_NONCE_SIZE: usize = 12; // 96 bits
pub const AES_GCM_TAG_SIZE: usize = 16; // 128 bits
pub const DATA_LEN_SIZE: usize = 4; // u32 for block length

pub struct BlockChain<Mode> {
    mode: Mode,
    /// Path to RocksDB database
    db_path: std::path::PathBuf,
}

struct Init {}

struct OpenChain {}

struct ReadOnly {
    db: rocksdb::DBWithThreadMode<SingleThreaded>,
}

struct ReadWrite {
    db: rocksdb::DBWithThreadMode<SingleThreaded>,
}

impl BlockChain<Init> {
    pub fn init(path: PathBuf) -> Result<Self> {
        Ok(Self {
            mode: Init {},
            db_path: path,
        })
    }
}

impl BlockChain<OpenChain> {
    pub fn open(path: PathBuf) -> Result<Self> {
        if path.exists() {
            Ok(Self {
                mode: OpenChain {},
                db_path: path,
            })
        } else {
            Err(anyhow!("Database path does not exist"))
        }
    }

    pub fn open_or_create(path: PathBuf) -> Result<BlockChain<OpenChain>> {
        if path.exists() {
            Ok(BlockChain {
                mode: OpenChain {},
                db_path: path,
            })
        } else {
            std::fs::create_dir_all(&path)
                .map_err(|e| anyhow!("Failed to create database directory: {}", e))?;
            Ok(BlockChain {
                mode: OpenChain {},
                db_path: path,
            })
        }
    }
}

impl BlockChain<ReadOnly> {
    pub fn open_read_only(open_blockchain: BlockChain<OpenChain>) -> Result<Self> {
        let db = RocksDbModel::read_only(&open_blockchain.db_path)
            .with_column_family("blocks")
            .with_column_family("signatures")
            .open()
            .map_err(|e| anyhow!("Failed to open RocksDB in read-only mode: {}", e))?;
        Ok(Self {
            mode: ReadOnly { db },
            db_path: open_blockchain.db_path,
        })
    }
    pub fn block_count(&self) -> Result<u64> {
        let count = self
            .mode
            .db
            .iterator_cf(
                self.mode.db.cf_handle("blocks").unwrap(),
                IteratorMode::Start,
            )
            .count() as u64;
        Ok(count)
    }
    pub fn get_block_by_height(&self, height: u64) -> Result<Block> {
        let block = (|| -> Result<Block> {
            let block_bytes = self
                .mode
                .db
                .get_cf(
                    self.mode.db.cf_handle("blocks").unwrap(),
                    height.to_le_bytes(),
                )
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
        let signature = self
            .mode
            .db
            .get_cf(
                self.mode.db.cf_handle("signatures").unwrap(),
                height.to_le_bytes(),
            )
            .map_err(|e| anyhow!("Failed to get signature by height: {}", e))?
            .ok_or_else(|| anyhow!("No signature found at height {}", height))?;
        Ok(signature)
    }

    pub fn validate(&self) -> Result<()> {
        let block_count = self.block_count()?;
        if block_count == 0 {
            return Ok(()); // Empty chain is valid
        }
        for i in 0..block_count {
            let block = self.get_block_by_height(i)?;
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
                let mut hashing_bytes = Vec::from(block.header_bytes());
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
        }
        Ok(())
    }
}

impl BlockChain<ReadWrite> {
    pub fn open_read_write(open_blockchain: BlockChain<OpenChain>) -> Result<Self> {
        let db = RocksDbModel::new(&open_blockchain.db_path)
            .with_column_family("blocks")
            .with_column_family("signatures")
            .open()
            .map_err(|e| anyhow!("Failed to open RocksDB in read-write mode: {}", e))?;
        return Ok(Self {
            mode: ReadWrite { db },
            db_path: open_blockchain.db_path,
        });
    }

    pub fn block_count(&self) -> Result<u64> {
        let read_only_chain = BlockChain::<ReadOnly>::open_read_only(BlockChain {
            mode: OpenChain {},
            db_path: self.db_path.clone(),
        })?;
        Ok(read_only_chain.block_count()?)
    }

    pub fn get_block_by_height(&self, height: u64) -> Result<Block> {
        let read_only_chain = BlockChain::<ReadOnly>::open_read_only(BlockChain {
            mode: OpenChain {},
            db_path: self.db_path.clone(),
        })?;
        Ok(read_only_chain.get_block_by_height(height)?)
    }

    pub fn put_block(&self, block_data: Vec<u8>) -> Result<u64> {
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
                return Ok(None);
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
}
