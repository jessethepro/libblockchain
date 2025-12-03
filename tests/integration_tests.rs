//! Integration tests for the libblockchain library
//!
//! These tests demonstrate how consumers would use the library to create
//! and manage blockchain blocks.

use anyhow::{Result, anyhow};
use libblockchain::block::Block;
use libblockchain::hybrid_encryption::hybrid_decrypt;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;

/// Generate a secure RSA key pair for testing
fn generate_rsa_keypair(bits: usize) -> Result<PKey<Private>> {
    if bits != 2048 && bits != 4096 {
        return Err(anyhow!("Key size must be 2048 or 4096 bits"));
    }

    let rsa =
        Rsa::generate(bits as u32).map_err(|e| anyhow!("Failed to generate RSA key: {}", e))?;

    PKey::from_rsa(rsa).map_err(|e| anyhow!("Failed to create PKey from RSA: {}", e))
}

#[test]
fn test_create_simple_blockchain() {
    let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
    let public_key_der = private_key
        .public_key_to_der()
        .expect("Failed to extract public key DER");
    let public_key =
        PKey::public_key_from_der(&public_key_der).expect("Failed to create public key");

    // Create genesis block
    let genesis = Block::new_genesis_block(b"Genesis block data".to_vec(), &public_key);
    assert_eq!(genesis.block_header.parent_hash, [0u8; 64]);

    // Create second block
    let block2 =
        Block::new_regular_block(genesis.block_hash, b"Block 2 data".to_vec(), &public_key);
    assert_eq!(block2.block_header.parent_hash, genesis.block_hash);

    // Create third block
    let block3 = Block::new_regular_block(block2.block_hash, b"Block 3 data".to_vec(), &public_key);
    assert_eq!(block3.block_header.parent_hash, block2.block_hash);

    // Verify chain integrity
    assert_ne!(genesis.block_hash, block2.block_hash);
    assert_ne!(block2.block_hash, block3.block_hash);
}

#[test]
fn test_genesis_block_properties() {
    let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
    let public_key_der = private_key
        .public_key_to_der()
        .expect("Failed to extract public key DER");
    let public_key =
        PKey::public_key_from_der(&public_key_der).expect("Failed to create public key");

    let genesis_data = b"Initial state data".to_vec();

    let genesis = Block::new_genesis_block(genesis_data.clone(), &public_key);

    // Genesis block should have zero parent hash
    assert_eq!(genesis.block_header.parent_hash, [0u8; 64]);

    // Decrypt and verify the data
    let decrypted = hybrid_decrypt(&private_key, genesis.block_data.clone())
        .expect("Failed to decrypt block data");
    assert_eq!(decrypted, genesis_data);

    // Should have a valid hash
    assert_ne!(genesis.block_hash, [0u8; 64]);

    // Should have version 1
    assert_eq!(genesis.block_header.version, 1);
}

#[test]
fn test_block_with_custom_data() {
    let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
    let public_key_der = private_key
        .public_key_to_der()
        .expect("Failed to extract public key DER");
    let public_key =
        PKey::public_key_from_der(&public_key_der).expect("Failed to create public key");

    // Simulate storing JSON data in blocks
    let json_data = br#"{"transaction": "transfer", "amount": 100}"#.to_vec();

    let genesis = Block::new_genesis_block(json_data.clone(), &public_key);
    let decrypted_json = hybrid_decrypt(&private_key, genesis.block_data.clone())
        .expect("Failed to decrypt block data");
    assert_eq!(decrypted_json, json_data);

    // Simulate binary data
    let binary_data = vec![0xFF, 0x00, 0xAA, 0x55];
    let block2 = Block::new_regular_block(genesis.block_hash, binary_data.clone(), &public_key);
    let decrypted_binary = hybrid_decrypt(&private_key, block2.block_data.clone())
        .expect("Failed to decrypt block data");
    assert_eq!(decrypted_binary, binary_data);
}

#[test]
fn test_hash_consistency() {
    let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
    let public_key_der = private_key
        .public_key_to_der()
        .expect("Failed to extract public key DER");
    let public_key =
        PKey::public_key_from_der(&public_key_der).expect("Failed to create public key");

    let block = Block::new_genesis_block(vec![1, 2, 3], &public_key);

    // Computing hash again should give the same result
    let hash1 = block.block_header.generate_block_hash();
    let hash2 = block.block_header.generate_block_hash();

    assert_eq!(hash1, hash2);
    assert_eq!(block.block_hash, hash1);
}

#[test]
fn test_different_blocks_have_different_hashes() {
    let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
    let public_key_der = private_key
        .public_key_to_der()
        .expect("Failed to extract public key DER");
    let public_key =
        PKey::public_key_from_der(&public_key_der).expect("Failed to create public key");

    let block1 = Block::new_genesis_block(vec![10, 20, 30], &public_key);
    let block2 = Block::new_genesis_block(vec![10, 20, 30], &public_key);

    // Same data but different blocks should produce different hashes (due to different UIDs/timestamps)
    assert_ne!(block1.block_hash, block2.block_hash);
}

#[test]
fn test_long_blockchain() {
    let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
    let public_key_der = private_key
        .public_key_to_der()
        .expect("Failed to extract public key DER");
    let public_key =
        PKey::public_key_from_der(&public_key_der).expect("Failed to create public key");

    let mut blocks = Vec::new();

    // Create genesis
    blocks.push(Block::new_genesis_block(b"Genesis".to_vec(), &public_key));

    // Create 100 more blocks
    for i in 1..=100 {
        let prev_hash = blocks.last().unwrap().block_hash;
        let data = format!("Block {}", i).into_bytes();
        blocks.push(Block::new_regular_block(prev_hash, data, &public_key));
    }

    // Verify chain integrity
    for i in 1..blocks.len() {
        assert_eq!(
            blocks[i].block_header.parent_hash,
            blocks[i - 1].block_hash,
            "Block {} doesn't link to block {}",
            i,
            i - 1
        );
    }

    assert_eq!(blocks.len(), 101);
}
