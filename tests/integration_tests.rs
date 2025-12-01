//! Integration tests for the libblockchain library
//!
//! These tests demonstrate how consumers would use the library to create
//! and manage blockchain blocks.

use libblockchain::block::Block;
use openssl::rsa::Rsa;
use openssl::pkey::{PKey, Private};
use openssl::x509::{X509Builder, X509NameBuilder};
use openssl::hash::MessageDigest;
use openssl::bn::BigNum;
use openssl::asn1::Asn1Time;
use anyhow::{anyhow, Result};
use libblockchain::hybrid_encryption::hybrid_decrypt_from_bytes;

/// Generate a secure RSA key pair for testing
fn generate_rsa_keypair(bits: usize) -> Result<PKey<Private>> {
    if bits != 2048 && bits != 4096 {
        return Err(anyhow!("Key size must be 2048 or 4096 bits"));
    }
    
    let rsa = Rsa::generate(bits as u32)
        .map_err(|e| anyhow!("Failed to generate RSA key: {}", e))?;
    
    PKey::from_rsa(rsa)
        .map_err(|e| anyhow!("Failed to create PKey from RSA: {}", e))
}

/// Generate a test X509 certificate
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
fn test_create_simple_blockchain() {
    let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
    let cert = generate_test_cert(&private_key).expect("Failed to generate certificate");
    
    // Create genesis block
    let genesis = Block::new_genesis_block(b"Genesis block data".to_vec(), cert.clone());
    assert_eq!(genesis.block_header.parent_hash, [0u8; 32]);

    // Create second block
    let block2 = Block::new_regular_block(genesis.block_hash, b"Block 2 data".to_vec(), cert.clone());
    assert_eq!(block2.block_header.parent_hash, genesis.block_hash);

    // Create third block
    let block3 = Block::new_regular_block(block2.block_hash, b"Block 3 data".to_vec(), cert);
    assert_eq!(block3.block_header.parent_hash, block2.block_hash);

    // Verify chain integrity
    assert_ne!(genesis.block_hash, block2.block_hash);
    assert_ne!(block2.block_hash, block3.block_hash);
}

#[test]
fn test_genesis_block_properties() {
    let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
    let cert = generate_test_cert(&private_key).expect("Failed to generate certificate");
    
    let genesis_data = b"Initial state data".to_vec();
    
    let genesis = Block::new_genesis_block(genesis_data.clone(), cert);

    // Genesis block should have zero parent hash
    assert_eq!(genesis.block_header.parent_hash, [0u8; 32]);
    
    // Decrypt and verify the data
    let decrypted = hybrid_decrypt_from_bytes(&private_key, &genesis.block_data)
        .expect("Failed to decrypt block data");
    assert_eq!(decrypted, genesis_data);
    
    // Should have a valid hash
    assert_ne!(genesis.block_hash, [0u8; 32]);
    
    // Should have version 1
    assert_eq!(genesis.block_header.version, 1);
}

#[test]
fn test_block_with_custom_data() {
    let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
    let cert = generate_test_cert(&private_key).expect("Failed to generate certificate");
    
    // Simulate storing JSON data in blocks
    let json_data = br#"{"transaction": "transfer", "amount": 100}"#.to_vec();
    
    let genesis = Block::new_genesis_block(json_data.clone(), cert.clone());
    let decrypted_json = hybrid_decrypt_from_bytes(&private_key, &genesis.block_data)
        .expect("Failed to decrypt block data");
    assert_eq!(decrypted_json, json_data);
    
    // Simulate binary data
    let binary_data = vec![0xFF, 0x00, 0xAA, 0x55];
    let block2 = Block::new_regular_block(genesis.block_hash, binary_data.clone(), cert);
    let decrypted_binary = hybrid_decrypt_from_bytes(&private_key, &block2.block_data)
        .expect("Failed to decrypt block data");
    assert_eq!(decrypted_binary, binary_data);
}

#[test]
fn test_hash_consistency() {
    let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
    let cert = generate_test_cert(&private_key).expect("Failed to generate certificate");
    
    let block = Block::new_genesis_block(vec![1, 2, 3], cert);
    
    // Computing hash again should give the same result
    let hash1 = block.block_header.generate_block_hash();
    let hash2 = block.block_header.generate_block_hash();
    
    assert_eq!(hash1, hash2);
    assert_eq!(block.block_hash, hash1);
}

#[test]
fn test_different_blocks_have_different_hashes() {
    let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
    let cert = generate_test_cert(&private_key).expect("Failed to generate certificate");
    
    let block1 = Block::new_genesis_block(vec![10, 20, 30], cert.clone());
    let block2 = Block::new_genesis_block(vec![10, 20, 30], cert);
    
    // Same data but different blocks should produce different hashes (due to different UIDs/timestamps)
    assert_ne!(block1.block_hash, block2.block_hash);
}

#[test]
fn test_long_blockchain() {
    let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
    let cert = generate_test_cert(&private_key).expect("Failed to generate certificate");
    
    let mut blocks = Vec::new();
    
    // Create genesis
    blocks.push(Block::new_genesis_block(b"Genesis".to_vec(), cert.clone()));
    
    // Create 100 more blocks
    for i in 1..=100 {
        let prev_hash = blocks.last().unwrap().block_hash;
        let data = format!("Block {}", i).into_bytes();
        blocks.push(Block::new_regular_block(prev_hash, data, cert.clone()));
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
