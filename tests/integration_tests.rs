//! Integration tests for the libblockchain library
//!
//! These tests demonstrate how consumers would use the library to create
//! and manage blockchain blocks.

use libblockchain::{Block, BlockHeaderHasher, GenesisBlock, RegularBlock, CertificateTools};

/// SHA-256 hasher implementation using CertificateTools
struct CertToolsHasher;

impl BlockHeaderHasher for CertToolsHasher {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        CertificateTools::hash_sha256(data)
            .expect("SHA-256 hashing failed")
    }

    fn hash_size(&self) -> usize {
        32
    }
}

#[test]
fn test_create_simple_blockchain() {
    let hasher = CertToolsHasher;

    // Create genesis block
    let genesis = Block::new_genesis(&hasher, b"Genesis block data".to_vec());
    assert_eq!(genesis.block_header.parent_hash, [0u8; 32]);

    // Create second block
    let block2 = Block::new_block(&hasher, genesis.block_hash, b"Block 2 data".to_vec());
    assert_eq!(block2.block_header.parent_hash, genesis.block_hash);

    // Create third block
    let block3 = Block::new_block(&hasher, block2.block_hash, b"Block 3 data".to_vec());
    assert_eq!(block3.block_header.parent_hash, block2.block_hash);

    // Verify chain integrity
    assert_ne!(genesis.block_hash, block2.block_hash);
    assert_ne!(block2.block_hash, block3.block_hash);
}

#[test]
fn test_genesis_block_properties() {
    let hasher = CertToolsHasher;
    let genesis_data = b"Initial state data".to_vec();
    
    let genesis = Block::new_genesis(&hasher, genesis_data.clone());

    // Genesis block should have zero parent hash
    assert_eq!(genesis.block_header.parent_hash, [0u8; 32]);
    
    // Should contain the data
    assert_eq!(genesis.block_data, genesis_data);
    
    // Should have a valid hash
    assert_ne!(genesis.block_hash, [0u8; 32]);
    
    // Should have version 1
    assert_eq!(genesis.block_header.version, 1);
}

#[test]
fn test_block_with_custom_data() {
    let hasher = CertToolsHasher;
    
    // Simulate storing JSON data in blocks
    let json_data = br#"{"transaction": "transfer", "amount": 100}"#.to_vec();
    
    let genesis = Block::new_genesis(&hasher, json_data.clone());
    assert_eq!(genesis.block_data, json_data);
    
    // Simulate binary data
    let binary_data = vec![0xFF, 0x00, 0xAA, 0x55];
    let block2 = Block::new_block(&hasher, genesis.block_hash, binary_data.clone());
    assert_eq!(block2.block_data, binary_data);
}

#[test]
fn test_hash_consistency() {
    let hasher = CertToolsHasher;
    
    let block = Block::new_genesis(&hasher, vec![1, 2, 3]);
    
    // Computing hash again should give the same result
    let hash1 = block.header_hash(&hasher);
    let hash2 = block.header_hash(&hasher);
    
    assert_eq!(hash1, hash2);
    assert_eq!(hash1.len(), 32);
}

#[test]
fn test_multiple_hashers() {
    // Test that different hashers can be used
    struct AlternateHasher;
    
    impl BlockHeaderHasher for AlternateHasher {
        fn hash(&self, data: &[u8]) -> Vec<u8> {
            // Different hashing algorithm
            let sum: u32 = data.iter().map(|&b| b as u32).sum();
            let mut result = vec![0u8; 32];
            result[0..4].copy_from_slice(&sum.to_le_bytes());
            result
        }
        
        fn hash_size(&self) -> usize {
            32
        }
    }
    
    let hasher1 = CertToolsHasher;
    let hasher2 = AlternateHasher;
    
    let block1 = Block::new_genesis(&hasher1, vec![10, 20, 30]);
    let block2 = Block::new_genesis(&hasher2, vec![10, 20, 30]);
    
    // Same data but different hashers should produce different hashes
    assert_ne!(block1.block_hash, block2.block_hash);
}

#[test]
fn test_long_blockchain() {
    let hasher = CertToolsHasher;
    
    let mut blocks = Vec::new();
    
    // Create genesis
    blocks.push(Block::new_genesis(&hasher, b"Genesis".to_vec()));
    
    // Create 100 more blocks
    for i in 1..=100 {
        let prev_hash = blocks.last().unwrap().block_hash;
        let data = format!("Block {}", i).into_bytes();
        blocks.push(Block::new_block(&hasher, prev_hash, data));
    }
    
    // Verify chain integrity
    for i in 1..blocks.len() {
        assert_eq!(
            blocks[i].block_header.parent_hash,
            blocks[i - 1].block_hash,
            "Block {} doesn't link to block {}", i, i - 1
        );
    }
    
    assert_eq!(blocks.len(), 101);
}
