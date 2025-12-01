//! Blockchain storage and management using SledDB
//!
//! This module provides persistent storage for blockchain blocks using Sled,
//! a high-performance embedded database.

use anyhow::{anyhow, Result};
use sled::Db;
use std::path::Path;
use crate::block::Block;

/// SledDB-backed blockchain storage
pub struct SledDB {
    /// Sled database instance
    db: Db,
    
    /// Tree for storing blocks by hash
    blocks: sled::Tree,
    
    /// Tree for storing block height -> hash mapping
    height_index: sled::Tree,
}

impl SledDB {
    /// Open or create a new SledDB blockchain database
    /// 
    /// # Arguments
    /// * `path` - Path to the database directory
    /// 
    /// # Returns
    /// A new SledDB instance
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = sled::open(path)
            .map_err(|e| anyhow!("Failed to open SledDB: {}", e))?;
        
        let blocks = db.open_tree("blocks")
            .map_err(|e| anyhow!("Failed to open blocks tree: {}", e))?;
        
        let height_index = db.open_tree("height_index")
            .map_err(|e| anyhow!("Failed to open height_index tree: {}", e))?;
        
        Ok(Self {
            db,
            blocks,
            height_index,
        })
    }
    
    /// Store a block in the database
    /// 
    /// # Arguments
    /// * `block` - The block to store
    /// * `height` - The block height (0 for genesis)
    pub fn insert_block(&self, block: &Block, height: u64) -> Result<()> {
        // Serialize block (using serde or custom serialization)
        let block_bytes = self.serialize_block(block)?;
        
        // Store block by hash
        self.blocks.insert(&block.block_hash, block_bytes)
            .map_err(|e| anyhow!("Failed to insert block: {}", e))?;
        
        // Store height -> hash mapping
        let height_bytes = height.to_be_bytes();
        self.height_index.insert(height_bytes, &block.block_hash[..])
            .map_err(|e| anyhow!("Failed to insert height index: {}", e))?;
        
        // Flush to ensure durability
        self.db.flush()
            .map_err(|e| anyhow!("Failed to flush database: {}", e))?;
        
        Ok(())
    }
    
    /// Get a block by its hash
    /// 
    /// # Arguments
    /// * `hash` - The block hash
    /// 
    /// # Returns
    /// The block if found, None otherwise
    pub fn get_block_by_hash(&self, hash: &[u8; 32]) -> Result<Option<Block>> {
        match self.blocks.get(hash)
            .map_err(|e| anyhow!("Failed to get block: {}", e))? {
            Some(bytes) => {
                let block = self.deserialize_block(&bytes)?;
                Ok(Some(block))
            }
            None => Ok(None)
        }
    }
    
    /// Get a block by its height
    /// 
    /// # Arguments
    /// * `height` - The block height
    /// 
    /// # Returns
    /// The block if found, None otherwise
    pub fn get_block_by_height(&self, height: u64) -> Result<Option<Block>> {
        let height_bytes = height.to_be_bytes();
        
        match self.height_index.get(height_bytes)
            .map_err(|e| anyhow!("Failed to get height index: {}", e))? {
            Some(hash_bytes) => {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&hash_bytes);
                self.get_block_by_hash(&hash)
            }
            None => Ok(None)
        }
    }
    
    /// Get the current blockchain height (number of blocks - 1)
    pub fn get_height(&self) -> Result<u64> {
        match self.height_index.last()
            .map_err(|e| anyhow!("Failed to get last height: {}", e))? {
            Some((height_bytes, _)) => {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&height_bytes);
                Ok(u64::from_be_bytes(bytes))
            }
            None => Ok(0) // Empty blockchain
        }
    }
    
    /// Get the latest block (tip of the chain)
    pub fn get_latest_block(&self) -> Result<Option<Block>> {
        let height = self.get_height()?;
        self.get_block_by_height(height)
    }
    
    /// Check if a block exists by hash
    pub fn block_exists(&self, hash: &[u8; 32]) -> Result<bool> {
        self.blocks.contains_key(hash)
            .map_err(|e| anyhow!("Failed to check block existence: {}", e))
    }
    
    /// Get the total number of blocks in the chain
    pub fn block_count(&self) -> Result<usize> {
        Ok(self.blocks.len())
    }
    
    /// Serialize a block to bytes
    /// 
    /// Format:
    /// - Block UID (16 bytes)
    /// - Version (4 bytes)
    /// - Parent hash (32 bytes)
    /// - Timestamp (8 bytes)
    /// - Nonce (8 bytes)
    /// - Block hash (32 bytes)
    /// - Data length (4 bytes)
    /// - Block data (variable)
    fn serialize_block(&self, block: &Block) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        
        // Header fields
        bytes.extend_from_slice(&block.block_header.block_uid);
        bytes.extend_from_slice(&block.block_header.version.to_le_bytes());
        bytes.extend_from_slice(&block.block_header.parent_hash);
        bytes.extend_from_slice(&block.block_header.timestamp.to_le_bytes());
        bytes.extend_from_slice(&block.block_header.nonce.to_le_bytes());
        
        // Block hash
        bytes.extend_from_slice(&block.block_hash);
        
        // Block data (with length prefix)
        let data_len = block.block_data.len() as u32;
        bytes.extend_from_slice(&data_len.to_le_bytes());
        bytes.extend_from_slice(&block.block_data);
        
        Ok(bytes)
    }
    
    /// Deserialize a block from bytes
    fn deserialize_block(&self, bytes: &[u8]) -> Result<Block> {
        if bytes.len() < 104 { // Minimum size without data
            return Err(anyhow!("Invalid block data: too short"));
        }
        
        let mut offset = 0;
        
        // Block UID (16 bytes)
        let mut block_uid = [0u8; 16];
        block_uid.copy_from_slice(&bytes[offset..offset + 16]);
        offset += 16;
        
        // Version (4 bytes)
        let version = u32::from_le_bytes([
            bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]
        ]);
        offset += 4;
        
        // Parent hash (32 bytes)
        let mut parent_hash = [0u8; 32];
        parent_hash.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;
        
        // Timestamp (8 bytes)
        let timestamp = u64::from_le_bytes([
            bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
            bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7]
        ]);
        offset += 8;
        
        // Nonce (8 bytes)
        let nonce = u64::from_le_bytes([
            bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
            bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7]
        ]);
        offset += 8;
        
        // Block hash (32 bytes)
        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;
        
        // Data length (4 bytes)
        let data_len = u32::from_le_bytes([
            bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]
        ]) as usize;
        offset += 4;
        
        // Block data
        if bytes.len() < offset + data_len {
            return Err(anyhow!("Invalid block data: data length mismatch"));
        }
        let block_data = bytes[offset..offset + data_len].to_vec();
        
        Ok(Block {
            block_header: crate::block::BlockHeader {
                block_uid,
                version,
                parent_hash,
                timestamp,
                nonce,
            },
            block_hash,
            block_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use openssl::rsa::Rsa;
    use openssl::pkey::{PKey, Private};
    use openssl::x509::{X509Builder, X509NameBuilder};
    use openssl::hash::MessageDigest;
    use openssl::bn::BigNum;
    use openssl::asn1::Asn1Time;

    fn generate_rsa_keypair(bits: usize) -> Result<PKey<Private>> {
        let rsa = Rsa::generate(bits as u32)
            .map_err(|e| anyhow!("Failed to generate RSA key: {}", e))?;
        
        PKey::from_rsa(rsa)
            .map_err(|e| anyhow!("Failed to create PKey from RSA: {}", e))
    }

    fn generate_test_cert(private_key: &PKey<Private>) -> Result<openssl::x509::X509> {
        let mut builder = X509Builder::new()
            .map_err(|e| anyhow!("Failed to create X509 builder: {}", e))?;
        
        builder.set_version(2)
            .map_err(|e| anyhow!("Failed to set version: {}", e))?;
        
        let serial = BigNum::from_u32(1)
            .map_err(|e| anyhow!("Failed to create serial: {}", e))?;
        let serial = serial.to_asn1_integer()
            .map_err(|e| anyhow!("Failed to convert serial: {}", e))?;
        builder.set_serial_number(&serial)
            .map_err(|e| anyhow!("Failed to set serial: {}", e))?;
        
        let mut name_builder = X509NameBuilder::new()
            .map_err(|e| anyhow!("Failed to create name builder: {}", e))?;
        name_builder.append_entry_by_text("CN", "Test Certificate")
            .map_err(|e| anyhow!("Failed to set CN: {}", e))?;
        let name = name_builder.build();
        builder.set_subject_name(&name)
            .map_err(|e| anyhow!("Failed to set subject: {}", e))?;
        builder.set_issuer_name(&name)
            .map_err(|e| anyhow!("Failed to set issuer: {}", e))?;
        
        let not_before = Asn1Time::days_from_now(0)
            .map_err(|e| anyhow!("Failed to create not_before: {}", e))?;
        let not_after = Asn1Time::days_from_now(365)
            .map_err(|e| anyhow!("Failed to create not_after: {}", e))?;
        builder.set_not_before(&not_before)
            .map_err(|e| anyhow!("Failed to set not_before: {}", e))?;
        builder.set_not_after(&not_after)
            .map_err(|e| anyhow!("Failed to set not_after: {}", e))?;
        
        builder.set_pubkey(private_key)
            .map_err(|e| anyhow!("Failed to set public key: {}", e))?;
        
        builder.sign(private_key, MessageDigest::sha256())
            .map_err(|e| anyhow!("Failed to sign certificate: {}", e))?;
        
        Ok(builder.build())
    }

    #[test]
    fn test_sled_db_creation() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let db = SledDB::new(temp_dir.path()).expect("Failed to create SledDB");
        
        assert_eq!(db.block_count().unwrap(), 0);
    }

    #[test]
    fn test_insert_and_retrieve_block() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let db = SledDB::new(temp_dir.path()).expect("Failed to create SledDB");
        
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let cert = generate_test_cert(&private_key).expect("Failed to generate certificate");
        
        let genesis = Block::new_genesis_block(b"Genesis data".to_vec(), cert);
        
        db.insert_block(&genesis, 0).expect("Failed to insert block");
        
        let retrieved = db.get_block_by_hash(&genesis.block_hash)
            .expect("Failed to get block")
            .expect("Block not found");
        
        assert_eq!(retrieved.block_hash, genesis.block_hash);
        assert_eq!(retrieved.block_header.block_uid, genesis.block_header.block_uid);
    }

    #[test]
    fn test_get_block_by_height() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let db = SledDB::new(temp_dir.path()).expect("Failed to create SledDB");
        
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let cert = generate_test_cert(&private_key).expect("Failed to generate certificate");
        
        let genesis = Block::new_genesis_block(b"Genesis".to_vec(), cert.clone());
        db.insert_block(&genesis, 0).expect("Failed to insert genesis");
        
        let block1 = Block::new_regular_block(genesis.block_hash, b"Block 1".to_vec(), cert);
        db.insert_block(&block1, 1).expect("Failed to insert block 1");
        
        let retrieved = db.get_block_by_height(1)
            .expect("Failed to get block")
            .expect("Block not found");
        
        assert_eq!(retrieved.block_hash, block1.block_hash);
    }

    #[test]
    fn test_get_latest_block() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let db = SledDB::new(temp_dir.path()).expect("Failed to create SledDB");
        
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let cert = generate_test_cert(&private_key).expect("Failed to generate certificate");
        
        let genesis = Block::new_genesis_block(b"Genesis".to_vec(), cert.clone());
        db.insert_block(&genesis, 0).expect("Failed to insert genesis");
        
        let block1 = Block::new_regular_block(genesis.block_hash, b"Block 1".to_vec(), cert);
        db.insert_block(&block1, 1).expect("Failed to insert block 1");
        
        let latest = db.get_latest_block()
            .expect("Failed to get latest block")
            .expect("No latest block");
        
        assert_eq!(latest.block_hash, block1.block_hash);
    }

    #[test]
    fn test_block_count() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let db = SledDB::new(temp_dir.path()).expect("Failed to create SledDB");
        
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let cert = generate_test_cert(&private_key).expect("Failed to generate certificate");
        
        assert_eq!(db.block_count().unwrap(), 0);
        
        let genesis = Block::new_genesis_block(b"Genesis".to_vec(), cert.clone());
        db.insert_block(&genesis, 0).expect("Failed to insert genesis");
        
        assert_eq!(db.block_count().unwrap(), 1);
        
        let block1 = Block::new_regular_block(genesis.block_hash, b"Block 1".to_vec(), cert);
        db.insert_block(&block1, 1).expect("Failed to insert block 1");
        
        assert_eq!(db.block_count().unwrap(), 2);
    }
}
