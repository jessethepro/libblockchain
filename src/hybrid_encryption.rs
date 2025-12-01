//! Hybrid encryption module combining RSA and AES-GCM
//!
//! This module provides secure encryption for large data using:
//! - RSA (2048/4096) for encrypting symmetric keys
//! - AES-256-GCM for encrypting actual data
//!
//! This approach combines the security of public-key cryptography with
//! the performance of symmetric encryption.

use anyhow::{anyhow, Result};
use openssl::pkey::{PKey, Private, Public};
use openssl::x509::X509;
use openssl::symm::Cipher;
use openssl::rsa::Padding;
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Container for hybrid-encrypted data
/// 
/// Format:
/// - `encrypted_aes_key`: RSA-encrypted AES-256 key (256 or 512 bytes)
/// - `nonce`: AES-GCM nonce (12 bytes, must be unique per encryption)
/// - `tag`: AES-GCM authentication tag (16 bytes)
/// - `ciphertext`: AES-GCM encrypted data (variable size)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridEncryptedData {
    /// RSA-encrypted AES key (256 bytes for RSA-2048, 512 for RSA-4096)
    pub encrypted_aes_key: Vec<u8>,
    
    /// AES-GCM nonce (12 bytes)
    pub nonce: Vec<u8>,
    
    /// AES-GCM authentication tag (16 bytes)
    pub tag: Vec<u8>,
    
    /// AES-GCM encrypted data (variable size)
    pub ciphertext: Vec<u8>,
}

impl HybridEncryptedData {
    /// Serialize to binary format for storage or transmission
    /// 
    /// Format:
    /// - [0..2]: Key length as u16 big-endian
    /// - [2..2+key_len]: Encrypted AES key
    /// - [2+key_len..2+key_len+12]: Nonce (12 bytes)
    /// - [2+key_len+12..2+key_len+28]: Tag (16 bytes)
    /// - [2+key_len+28..]: Ciphertext
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Length prefix for encrypted_aes_key (2 bytes)
        let key_len = self.encrypted_aes_key.len() as u16;
        bytes.extend_from_slice(&key_len.to_be_bytes());
        
        // Encrypted AES key
        bytes.extend_from_slice(&self.encrypted_aes_key);
        
        // Nonce (12 bytes)
        bytes.extend_from_slice(&self.nonce);
        
        // Tag (16 bytes)
        bytes.extend_from_slice(&self.tag);
        
        // Ciphertext
        bytes.extend_from_slice(&self.ciphertext);
        
        bytes
    }
    
    /// Deserialize from binary format
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 2 {
            return Err(anyhow!("Invalid encrypted data: too short"));
        }
        
        // Read key length
        let key_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        
        if bytes.len() < 2 + key_len + 12 + 16 {
            return Err(anyhow!("Invalid encrypted data: incomplete"));
        }
        
        // Extract components
        let encrypted_aes_key = bytes[2..2 + key_len].to_vec();
        let nonce = bytes[2 + key_len..2 + key_len + 12].to_vec();
        let tag = bytes[2 + key_len + 12..2 + key_len + 28].to_vec();
        let ciphertext = bytes[2 + key_len + 28..].to_vec();
        
        Ok(Self {
            encrypted_aes_key,
            nonce,
            tag,
            ciphertext,
        })
    }
    
    /// Get the overhead size in bytes (not including actual data)
    pub fn overhead_size(&self) -> usize {
        2 + self.encrypted_aes_key.len() + 12 + 16
    }
}

/// Encrypt data using hybrid encryption (RSA + AES-GCM)
/// 
/// # Process
/// 1. Extract public key from X509 certificate
/// 2. Generate random AES-256 key
/// 3. Generate random 12-byte nonce
/// 4. Encrypt plaintext with AES-256-GCM
/// 5. Encrypt AES key with RSA public key
/// 6. Return container with both encrypted components
/// 
/// # Arguments
/// * `cert` - X509 certificate containing RSA public key (2048 or 4096 bits recommended)
/// * `plaintext` - Data to encrypt (any size)
/// 
/// # Returns
/// Container with RSA-encrypted AES key and AES-encrypted data
pub fn hybrid_encrypt(
    cert: &X509,
    plaintext: &[u8],
) -> Result<HybridEncryptedData> {
    // Extract public key from certificate
    let rsa_public = cert.public_key()
        .map_err(|e| anyhow!("Failed to extract public key from certificate: {}", e))?;
    // 1. Generate random AES-256 key (32 bytes)
    let aes_key: [u8; 32] = rand::random();
    
    // 2. Encrypt data with AES-256-GCM
    let (ciphertext, nonce, tag) = encrypt_aes_256_gcm(plaintext, &aes_key)?;
    
    // 3. Encrypt AES key with RSA-OAEP
    let encrypted_aes_key = encrypt_rsa_oaep(&aes_key, &rsa_public)?;
    
    Ok(HybridEncryptedData {
        encrypted_aes_key,
        nonce,
        tag,
        ciphertext,
    })
}

/// Decrypt data encrypted with hybrid encryption
/// 
/// # Process
/// 1. Decrypt AES key using RSA private key
/// 2. Decrypt and authenticate ciphertext with AES-GCM
/// 
/// # Arguments
/// * `rsa_private` - RSA private key matching the public key used for encryption
/// * `data` - Encrypted data container
/// 
/// # Returns
/// Decrypted plaintext
/// 
/// # Errors
/// Returns error if:
/// - RSA decryption fails (wrong key or corrupted data)
/// - AES decryption fails (corrupted data or authentication failure)
pub fn hybrid_decrypt(
    rsa_private: &PKey<Private>,
    data: &HybridEncryptedData,
) -> Result<Vec<u8>> {
    // 1. Decrypt AES key with RSA-OAEP
    let aes_key = decrypt_rsa_oaep(&data.encrypted_aes_key, rsa_private)?;
    
    // Validate AES key length
    if aes_key.len() != 32 {
        return Err(anyhow!("Invalid AES key length: expected 32 bytes, got {}", aes_key.len()));
    }
    
    // 2. Decrypt and verify authentication tag
    let plaintext = decrypt_aes_256_gcm(
        &data.ciphertext,
        &aes_key,
        &data.nonce,
        &data.tag,
    )?;
    
    Ok(plaintext)
}

/// Encrypt data and serialize to bytes in one step
pub fn hybrid_encrypt_to_bytes(
    cert: &X509,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let encrypted = hybrid_encrypt(cert, plaintext)?;
    Ok(encrypted.to_bytes())
}

/// Decrypt data from bytes in one step
pub fn hybrid_decrypt_from_bytes(
    rsa_private: &PKey<Private>,
    encrypted_bytes: &[u8],
) -> Result<Vec<u8>> {
    let encrypted = HybridEncryptedData::from_bytes(encrypted_bytes)?;
    hybrid_decrypt(rsa_private, &encrypted)
}

// ===== Symmetric Encryption (AES-256-GCM) =====
    
/// Encrypt data using AES-256-GCM
/// 
/// Returns: (ciphertext, nonce, tag)
pub fn encrypt_aes_256_gcm(plaintext: &[u8], key: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    if key.len() != 32 {
        return Err(anyhow!("AES-256 requires a 32-byte key"));
    }
    
    // Generate random 12-byte nonce
    let mut nonce = vec![0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    
    let cipher = Cipher::aes_256_gcm();
    let mut tag = vec![0u8; 16];
    
    let ciphertext = openssl::symm::encrypt_aead(
        cipher,
        key,
        Some(&nonce),
        &[],
        plaintext,
        &mut tag,
    ).map_err(|e| anyhow!("AES-GCM encryption failed: {}", e))?;
    
    Ok((ciphertext, nonce, tag))
}

/// Decrypt data using AES-256-GCM
pub fn decrypt_aes_256_gcm(ciphertext: &[u8], key: &[u8], nonce: &[u8], tag: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(anyhow!("AES-256 requires a 32-byte key"));
    }
    
    let cipher = Cipher::aes_256_gcm();
    
    let plaintext = openssl::symm::decrypt_aead(
        cipher,
        key,
        Some(nonce),
        &[],
        ciphertext,
        tag,
    ).map_err(|e| anyhow!("AES-GCM decryption failed (wrong key or tampered data): {}", e))?;
    
    Ok(plaintext)
}

// ===== Asymmetric Encryption (RSA-OAEP) =====

/// Encrypt data using RSA-OAEP with SHA-256
pub fn encrypt_rsa_oaep(plaintext: &[u8], public_key: &PKey<Public>) -> Result<Vec<u8>> {
    let rsa = public_key.rsa()
        .map_err(|e| anyhow!("Failed to get RSA key: {}", e))?;
    
    let mut ciphertext = vec![0u8; rsa.size() as usize];
    
    let len = rsa.public_encrypt(plaintext, &mut ciphertext, Padding::PKCS1_OAEP)
        .map_err(|e| anyhow!("RSA encryption failed: {}", e))?;
    
    ciphertext.truncate(len);
    Ok(ciphertext)
}

/// Decrypt data using RSA-OAEP with SHA-256
pub fn decrypt_rsa_oaep(ciphertext: &[u8], private_key: &PKey<Private>) -> Result<Vec<u8>> {
    let rsa = private_key.rsa()
        .map_err(|e| anyhow!("Failed to get RSA key: {}", e))?;
    
    let mut plaintext = vec![0u8; rsa.size() as usize];
    
    let len = rsa.private_decrypt(ciphertext, &mut plaintext, Padding::PKCS1_OAEP)
        .map_err(|e| anyhow!("RSA decryption failed: {}", e))?;
    
    plaintext.truncate(len);
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::rsa::Rsa;

    /// Generate a secure RSA key pair for hybrid encryption
/// 
/// # Arguments
/// * `bits` - Key size in bits (2048 or 4096 recommended)
/// 
/// # Returns
/// RSA private key (public key can be derived from it)
pub fn generate_rsa_keypair(bits: usize) -> Result<PKey<Private>> {
    if bits != 2048 && bits != 4096 {
        return Err(anyhow!("Key size must be 2048 or 4096 bits"));
    }
    
    let rsa = Rsa::generate(bits as u32)
        .map_err(|e| anyhow!("Failed to generate RSA key: {}", e))?;
    
    PKey::from_rsa(rsa)
        .map_err(|e| anyhow!("Failed to create PKey from RSA: {}", e))
}

    #[test]
    fn test_hybrid_encryption_rsa2048() {
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let cert = generate_test_cert(&private_key).expect("Failed to generate test certificate");
        
        let plaintext = b"Hello, hybrid encryption with RSA-2048!";
        
        // Encrypt
        let encrypted = hybrid_encrypt(&cert, plaintext).expect("Encryption failed");
        assert_eq!(encrypted.encrypted_aes_key.len(), 256); // RSA-2048 produces 256 bytes
        
        // Decrypt
        let decrypted = hybrid_decrypt(&private_key, &encrypted).expect("Decryption failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_hybrid_encryption_rsa4096() {
        let private_key = generate_rsa_keypair(4096).expect("Failed to generate key");
        let cert = generate_test_cert(&private_key).expect("Failed to generate test certificate");
        
        let plaintext = b"Hello, hybrid encryption with RSA-4096!";
        
        // Encrypt
        let encrypted = hybrid_encrypt(&cert, plaintext).expect("Encryption failed");
        assert_eq!(encrypted.encrypted_aes_key.len(), 512); // RSA-4096 produces 512 bytes
        
        // Decrypt
        let decrypted = hybrid_decrypt(&private_key, &encrypted).expect("Decryption failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_large_data_encryption() {
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let cert = generate_test_cert(&private_key).expect("Failed to generate test certificate");
        
        // 1 MB of data
        let plaintext: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
        
        // Encrypt
        let encrypted = hybrid_encrypt(&cert, &plaintext).expect("Encryption failed");
        
        // Decrypt
        let decrypted = hybrid_decrypt(&private_key, &encrypted).expect("Decryption failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_serialization() {
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let cert = generate_test_cert(&private_key).expect("Failed to generate test certificate");
        
        let plaintext = b"Test serialization";
        
        // Encrypt and serialize
        let encrypted = hybrid_encrypt(&cert, plaintext).expect("Encryption failed");
        let bytes = encrypted.to_bytes();
        
        // Deserialize and decrypt
        let deserialized = HybridEncryptedData::from_bytes(&bytes).expect("Deserialization failed");
        let decrypted = hybrid_decrypt(&private_key, &deserialized).expect("Decryption failed");
        
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tampering_detection() {
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let cert = generate_test_cert(&private_key).expect("Failed to generate test certificate");
        
        let plaintext = b"Tamper test";
        
        // Encrypt
        let mut encrypted = hybrid_encrypt(&cert, plaintext).expect("Encryption failed");
        
        // Tamper with ciphertext
        encrypted.ciphertext[0] ^= 0xFF;
        
        // Decryption should fail due to authentication tag mismatch
        let result = hybrid_decrypt(&private_key, &encrypted);
        assert!(result.is_err(), "Should fail on tampered data");
    }

    #[test]
    fn test_wrong_key_fails() {
        let private_key1 = generate_rsa_keypair(2048).expect("Failed to generate key");
        let cert1 = generate_test_cert(&private_key1).expect("Failed to generate test certificate");
        
        let private_key2 = generate_rsa_keypair(2048).expect("Failed to generate key");
        
        let plaintext = b"Wrong key test";
        
        // Encrypt with key1
        let encrypted = hybrid_encrypt(&cert1, plaintext).expect("Encryption failed");
        
        // Try to decrypt with key2 (should fail)
        let result = hybrid_decrypt(&private_key2, &encrypted);
        assert!(result.is_err(), "Should fail with wrong key");
    }

    #[test]
    fn test_overhead_calculation() {
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let cert = generate_test_cert(&private_key).expect("Failed to generate test certificate");
        
        let plaintext = b"Test overhead";
        let encrypted = hybrid_encrypt(&cert, plaintext).expect("Encryption failed");
        
        // Overhead = length_prefix(2) + encrypted_key(256) + nonce(12) + tag(16) = 286 bytes
        assert_eq!(encrypted.overhead_size(), 286);
    }

    /// Generate a test X509 certificate for testing
    fn generate_test_cert(private_key: &PKey<Private>) -> Result<X509> {
        use openssl::x509::X509Builder;
        use openssl::x509::X509NameBuilder;
        use openssl::hash::MessageDigest;
        use openssl::bn::BigNum;
        use openssl::asn1::Asn1Time;
        
        let mut builder = X509Builder::new()
            .map_err(|e| anyhow!("Failed to create X509 builder: {}", e))?;
        
        // Set version to X509v3
        builder.set_version(2)
            .map_err(|e| anyhow!("Failed to set version: {}", e))?;
        
        // Generate serial number
        let serial = BigNum::from_u32(1)
            .map_err(|e| anyhow!("Failed to create serial: {}", e))?;
        let serial = serial.to_asn1_integer()
            .map_err(|e| anyhow!("Failed to convert serial: {}", e))?;
        builder.set_serial_number(&serial)
            .map_err(|e| anyhow!("Failed to set serial: {}", e))?;
        
        // Set subject name
        let mut name_builder = X509NameBuilder::new()
            .map_err(|e| anyhow!("Failed to create name builder: {}", e))?;
        name_builder.append_entry_by_text("CN", "Test Certificate")
            .map_err(|e| anyhow!("Failed to set CN: {}", e))?;
        let name = name_builder.build();
        builder.set_subject_name(&name)
            .map_err(|e| anyhow!("Failed to set subject: {}", e))?;
        builder.set_issuer_name(&name)
            .map_err(|e| anyhow!("Failed to set issuer: {}", e))?;
        
        // Set validity period
        let not_before = Asn1Time::days_from_now(0)
            .map_err(|e| anyhow!("Failed to create not_before: {}", e))?;
        let not_after = Asn1Time::days_from_now(365)
            .map_err(|e| anyhow!("Failed to create not_after: {}", e))?;
        builder.set_not_before(&not_before)
            .map_err(|e| anyhow!("Failed to set not_before: {}", e))?;
        builder.set_not_after(&not_after)
            .map_err(|e| anyhow!("Failed to set not_after: {}", e))?;
        
        // Set public key
        builder.set_pubkey(private_key)
            .map_err(|e| anyhow!("Failed to set public key: {}", e))?;
        
        // Sign the certificate
        builder.sign(private_key, MessageDigest::sha256())
            .map_err(|e| anyhow!("Failed to sign certificate: {}", e))?;
        
        Ok(builder.build())
    }
}
