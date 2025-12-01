//! Integration tests for the libblockchain library
//!
//! These tests demonstrate how consumers would use the library to create
//! and manage blockchain blocks.

use libblockchain::Block;

#[test]
fn test_create_simple_blockchain() {
    // Create genesis block
    let genesis = Block::new_genesis_block(b"Genesis block data".to_vec());
    assert_eq!(genesis.block_header.parent_hash, [0u8; 32]);

    // Create second block
    let block2 = Block::new_regular_block(genesis.block_hash, b"Block 2 data".to_vec());
    assert_eq!(block2.block_header.parent_hash, genesis.block_hash);

    // Create third block
    let block3 = Block::new_regular_block(block2.block_hash, b"Block 3 data".to_vec());
    assert_eq!(block3.block_header.parent_hash, block2.block_hash);

    // Verify chain integrity
    assert_ne!(genesis.block_hash, block2.block_hash);
    assert_ne!(block2.block_hash, block3.block_hash);
}

#[test]
fn test_genesis_block_properties() {
    let genesis_data = b"Initial state data".to_vec();
    
    let genesis = Block::new_genesis_block(genesis_data.clone());

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
    // Simulate storing JSON data in blocks
    let json_data = br#"{"transaction": "transfer", "amount": 100}"#.to_vec();
    
    let genesis = Block::new_genesis_block(json_data.clone());
    assert_eq!(genesis.block_data, json_data);
    
    // Simulate binary data
    let binary_data = vec![0xFF, 0x00, 0xAA, 0x55];
    let block2 = Block::new_regular_block(genesis.block_hash, binary_data.clone());
    assert_eq!(block2.block_data, binary_data);
}

#[test]
fn test_hash_consistency() {
    let block = Block::new_genesis_block(vec![1, 2, 3]);
    
    // Computing hash again should give the same result
    let hash1 = block.block_header.generate_block_hash();
    let hash2 = block.block_header.generate_block_hash();
    
    assert_eq!(hash1, hash2);
    assert_eq!(block.block_hash, hash1);
}

#[test]
fn test_different_blocks_have_different_hashes() {
    let block1 = Block::new_genesis_block(vec![10, 20, 30]);
    let block2 = Block::new_genesis_block(vec![10, 20, 30]);
    
    // Same data but different blocks should produce different hashes (due to different UIDs/timestamps)
    assert_ne!(block1.block_hash, block2.block_hash);
}

#[test]
fn test_long_blockchain() {
    let mut blocks = Vec::new();
    
    // Create genesis
    blocks.push(Block::new_genesis_block(b"Genesis".to_vec()));
    
    // Create 100 more blocks
    for i in 1..=100 {
        let prev_hash = blocks.last().unwrap().block_hash;
        let data = format!("Block {}", i).into_bytes();
        blocks.push(Block::new_regular_block(prev_hash, data));
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
