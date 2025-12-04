//! Secure storage for application private key using the secrecy crate
//!
//! This module provides a secure in-memory container for the application's private key
//! with automatic zeroization on drop to prevent key material from lingering in memory.

use crate::block::Block;
use anyhow::{Context, Result};
use openssl::pkey::{PKey, Private};
use secrecy::{ExposeSecret, SecretBox, zeroize::Zeroize};
use std::fmt;

/// A securely stored private key that implements Zeroize
#[derive(Clone)]
struct SecurePrivateKey {
    der_bytes: Vec<u8>,
}

impl Zeroize for SecurePrivateKey {
    fn zeroize(&mut self) {
        self.der_bytes.zeroize();
    }
}

impl fmt::Debug for SecurePrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecurePrivateKey")
            .field("der_bytes", &"<redacted>")
            .finish()
    }
}

/// Secure container for the application's private key
///
/// Uses the `secrecy` crate to ensure the private key material is:
/// - Protected from accidental exposure (won't appear in debug output)
/// - Automatically zeroized when dropped
/// - Only accessible through explicit `expose_secret()` calls
pub struct AppKeyStore {
    private_key: SecretBox<SecurePrivateKey>,
    pub public_key: PKey<openssl::pkey::Public>,
}

impl AppKeyStore {
    /// Create a new AppKeyStore from a `PKey<Private>`
    ///
    /// # Arguments
    /// * `key` - The private key to store securely
    ///
    /// # Returns
    /// * `Result<Self>` - The secure key store or an error
    fn new(key: PKey<Private>) -> Result<Self> {
        let der_bytes = key
            .private_key_to_der()
            .context("Failed to convert private key to DER")?;

        let secure_key = SecurePrivateKey { der_bytes };

        // Extract public key from private key
        let public_key_der = key
            .public_key_to_der()
            .context("Failed to extract public key to DER")?;
        let public_key = PKey::public_key_from_der(&public_key_der)
            .context("Failed to reconstruct public key from DER")?;

        Ok(Self {
            private_key: SecretBox::new(Box::new(secure_key)),
            public_key,
        })
    }

    /// Load a private key from PEM file and store it securely
    ///
    /// # Arguments
    /// * `pem_path` - Path to the PEM-encoded private key file
    /// * `password` - Optional password if the key is encrypted
    ///
    /// # Returns
    /// * `Result<Self>` - The secure key store or an error
    pub fn from_pem_file(pem_path: &str, password: Option<&str>) -> Result<Self> {
        let pem_data = std::fs::read(pem_path)
            .context(format!("Failed to read private key from {}", pem_path))?;

        let key = if let Some(pwd) = password {
            PKey::private_key_from_pem_passphrase(&pem_data, pwd.as_bytes())
                .context("Failed to decrypt private key with password")?
        } else {
            PKey::private_key_from_pem(&pem_data).context("Failed to parse private key PEM")?
        };

        Self::new(key)
    }

    /// Decrypt block data using the private key without exposing it
    ///
    /// This method performs decryption while keeping the private key
    /// inside the Secret wrapper, minimizing exposure.
    ///
    /// # Arguments
    /// * `block` - The encrypted block to decrypt
    ///
    /// # Returns
    /// * `Result<Vec<u8>>` - The decrypted block data
    pub fn decrypt_block_data(&self, block: Block) -> Result<Vec<u8>> {
        // Temporarily reconstruct the key only for the duration of this operation
        let der_bytes = &self.private_key.expose_secret().der_bytes;
        let pkey = PKey::private_key_from_der(der_bytes)
            .context("Failed to reconstruct private key from secure storage")?;

        use crate::hybrid_encryption::{
            HybridEncryptedData, decrypt_aes_256_gcm, decrypt_rsa_oaep,
        };
        let data = HybridEncryptedData::from_bytes(&block.block_data)?;

        // 1. Decrypt AES key with RSA-OAEP
        let aes_key = decrypt_rsa_oaep(&data.encrypted_aes_key, &pkey)?;

        // Validate AES key length
        use anyhow::anyhow;
        if aes_key.len() != 32 {
            return Err(anyhow!(
                "Invalid AES key length: expected 32 bytes, got {}",
                aes_key.len()
            ));
        }

        // 2. Decrypt and verify authentication tag
        let plaintext = decrypt_aes_256_gcm(&data.ciphertext, &aes_key, &data.nonce, &data.tag)?;

        Ok(plaintext)
    }
}

impl fmt::Debug for AppKeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppKeyStore")
            .field("private_key", &"<securely stored>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::rsa::Rsa;

    #[test]
    fn test_debug_no_leak() {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let store = AppKeyStore::new(pkey).unwrap();

        let debug_str = format!("{:?}", store);
        // Ensure no key material appears in debug output
        assert!(!debug_str.contains("der_bytes"));
        assert!(debug_str.contains("securely stored"));
    }
}
