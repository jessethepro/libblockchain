//! Block structure for a blockchain implementation.
//!
//! Each block contains one block transaction and maintains the blockchain integrity
//! through cryptographic hashing and linking to previous blocks.

pub const BLOCK_VERSION: u32 = 1;
use crate::hybrid_encryption::hybrid_encrypt;
use anyhow::{Result, anyhow};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
/// Core header for a block in a blockchain.
/// This struct contains only cryptographically relevant data for hash calculations.
/// Block height is handled separately as database metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    /// Block Unique Identifier
    pub block_uid: [u8; 16],

    /// Header version to support upgrades.
    pub version: u32,

    /// Hash of the parent block (previous block).
    pub parent_hash: [u8; 64],

    /// Timestamp of block creation (UNIX epoch seconds).
    pub timestamp: u64,

    /// Nonce for proof-of-work or other consensus algorithms.
    pub nonce: u64,
}

impl BlockHeader {
    /// Create a fully constructed new header convenience constructor.
    /// Note: block_height is handled separately as database metadata.
    pub fn new(parent_hash: [u8; 64]) -> (Self, [u8; 64]) {
        use rand::Rng;
        use std::time::{SystemTime, UNIX_EPOCH};
        use uuid::Uuid;

        let block_uid = Uuid::new_v4().as_bytes().to_owned();
        let version = BLOCK_VERSION;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        let nonce: u64 = rand::rng().random();
        let header = Self {
            block_uid,
            version,
            parent_hash,
            timestamp,
            nonce,
        };
        let block_hash = (|| {
            let hash_vec = openssl::hash::hash(MessageDigest::sha512(), &header.get_bytes())
                .expect("SHA-512 hashing failed")
                .to_vec();
            let mut hash = [0u8; 64];
            hash.copy_from_slice(&hash_vec[..64]);
            hash
        })();
        (header, block_hash)
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.block_uid);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.parent_hash);
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        bytes
    }

    pub fn generate_block_hash(&self) -> [u8; 64] {
        let hash_vec = openssl::hash::hash(MessageDigest::sha512(), &self.get_bytes())
            .expect("SHA-512 hashing failed")
            .to_vec();
        let mut hash = [0u8; 64];
        hash.copy_from_slice(&hash_vec[..64]);
        hash
    }
}

/// Represents a block in the blockchain
#[derive(Debug, Clone)]
pub struct Block {
    /// Block Header (cryptographically relevant data only)
    pub block_header: BlockHeader,

    /// This block's cryptographic hash (serialized header + block_data)
    pub block_hash: [u8; 64],

    /// Application-specific block data (opaque to this library)
    pub block_data: Vec<u8>,
}

impl Block {
    /// Regular constructor for Block
    pub fn new_regular_block(
        parent_hash: [u8; 64],
        block_data: Vec<u8>,
        public_key: &PKey<Public>,
    ) -> Self {
        let encrypted_data =
            hybrid_encrypt(public_key, &block_data).expect("Failed to encrypt block data");
        let (header, block_hash) = BlockHeader::new(parent_hash);
        Self {
            block_header: header,
            block_hash: block_hash,
            block_data: encrypted_data,
        }
    }
    /// Genesis block constructor
    pub fn new_genesis_block(block_data: Vec<u8>, public_key: &PKey<Public>) -> Self {
        let encrypted_data =
            hybrid_encrypt(public_key, &block_data).expect("Failed to encrypt block data");
        let (header, block_hash) = BlockHeader::new([0u8; 64]);
        Self {
            block_header: header,
            block_hash: block_hash,
            block_data: encrypted_data,
        }
    }

    /// Decrypt and retrieve the block data
    ///
    /// Takes a block and decrypts its `block_data` using the provided private key.
    /// This is typically used after retrieving a block from the blockchain.
    ///
    /// # Arguments
    /// * `block` - The block containing encrypted data
    /// * `private_key` - RSA private key corresponding to the certificate used for encryption
    ///
    /// # Returns
    /// - `Ok(Vec<u8>)` - The decrypted block data as bytes
    /// - `Err(_)` if decryption fails (wrong key, corrupted data, etc.)
    ///
    /// # Example
    /// ```no_run
    /// # use libblockchain::block::Block;
    /// # use openssl::pkey::PKey;
    /// # fn example(block: Block, private_key: &PKey<openssl::pkey::Private>) -> anyhow::Result<()> {
    /// let decrypted_data = Block::get_block_data(block, private_key)?;
    /// // Use decrypted_data as needed
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_block_data(block: Block, private_key: &PKey<Private>) -> Result<Vec<u8>> {
        use crate::hybrid_encryption::{
            HybridEncryptedData, decrypt_aes_256_gcm, decrypt_rsa_oaep,
        };
        let data = HybridEncryptedData::from_bytes(&block.block_data)?;

        // 1. Decrypt AES key with RSA-OAEP
        let aes_key = decrypt_rsa_oaep(&data.encrypted_aes_key, private_key)?;

        // Validate AES key length
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

    pub fn serialize_block(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // Serialize header
        bytes.extend_from_slice(&self.block_header.get_bytes());
        // Serialize block hash
        bytes.extend_from_slice(&self.block_hash);
        // Serialize block data length
        let data_len = self.block_data.len() as u32;
        bytes.extend_from_slice(&data_len.to_le_bytes());
        // Serialize block data
        bytes.extend_from_slice(&self.block_data);
        bytes
    }
}

pub fn deserialize_block(data: &[u8]) -> Result<Block> {
    // Header: uid(16) + version(4) + parent_hash(64) + timestamp(8) + nonce(8) = 100 bytes
    // Hash: 64 bytes
    // Data length: 4 bytes
    // Minimum: 100 + 64 + 4 = 168 bytes
    const UUID_LEN: usize = 16;
    const VERSION_LEN: usize = 4;
    const HASH_LEN: usize = 64;
    const TIMESTAMP_LEN: usize = 8;
    const NONCE_LEN: usize = 8;
    const HEADER_LEN: usize = UUID_LEN + VERSION_LEN + HASH_LEN + TIMESTAMP_LEN + NONCE_LEN;
    const DATA_LENGTH_LEN: usize = 4;
    const MINIMUM_LEN: usize = HEADER_LEN + HASH_LEN + DATA_LENGTH_LEN;
    let mut index = 0;
    if data.len() < MINIMUM_LEN {
        return Err(anyhow!("Not enough data for header, hash, and length"));
    }

    // Deserialize header (100 bytes total)
    let block_uid = {
        let mut uid = [0u8; UUID_LEN];
        uid.copy_from_slice(&data[index..index + UUID_LEN]);
        index += UUID_LEN;
        uid
    };
    let version = u32::from_le_bytes(data[index..index + VERSION_LEN].try_into().unwrap());
    index += VERSION_LEN;
    let parent_hash = {
        let mut phash = [0u8; HASH_LEN];
        phash.copy_from_slice(&data[index..index + HASH_LEN]);
        index += HASH_LEN;
        phash
    };
    let timestamp = u64::from_le_bytes(data[index..index + TIMESTAMP_LEN].try_into().unwrap());
    index += TIMESTAMP_LEN;
    let nonce = u64::from_le_bytes(data[index..index + NONCE_LEN].try_into().unwrap());
    index += NONCE_LEN;
    let header = BlockHeader {
        block_uid,
        version,
        parent_hash,
        timestamp,
        nonce,
    };

    // Deserialize block hash (64 bytes)
    let mut block_hash = [0u8; HASH_LEN];
    block_hash.copy_from_slice(&data[index..index + HASH_LEN]);
    index += HASH_LEN;

    // Deserialize block data length (4 bytes)
    let data_len =
        u32::from_le_bytes(data[index..index + DATA_LENGTH_LEN].try_into().unwrap()) as usize;
    index += DATA_LENGTH_LEN;

    if data.len() < index + data_len {
        return Err(anyhow!("Not enough space for block data")); // Not enough data for block data
    }

    // Deserialize block data
    let block_data = data[index..index + data_len].to_vec();

    Ok(Block {
        block_header: header,
        block_hash,
        block_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid_encryption::hybrid_decrypt;
    use anyhow::{Result, anyhow};
    use openssl::pkey::{PKey, Private};
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

        let rsa =
            Rsa::generate(bits as u32).map_err(|e| anyhow!("Failed to generate RSA key: {}", e))?;

        PKey::from_rsa(rsa).map_err(|e| anyhow!("Failed to create PKey from RSA: {}", e))
    }

    #[test]
    fn test_block_header_creation() {
        let parent_hash = [1u8; 64];
        let (header, block_hash) = BlockHeader::new(parent_hash);

        assert_eq!(header.version, BLOCK_VERSION);
        assert_eq!(header.parent_hash, parent_hash);
        assert!(header.timestamp > 0);
        assert_eq!(header.block_uid.len(), 16); // UUID is 16 bytes
        assert_ne!(block_hash, [0u8; 64]); // Hash should be generated
    }

    #[test]
    fn test_genesis_block_has_zero_parent_hash() {
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");

        let block_data = vec![1, 2, 3, 4];
        // Extract public key from private key
        let public_key_der = private_key
            .public_key_to_der()
            .expect("Failed to extract public key");
        let public_key =
            PKey::public_key_from_der(&public_key_der).expect("Failed to parse public key");
        let genesis = Block::new_genesis_block(block_data.clone(), &public_key);

        assert_eq!(genesis.block_header.parent_hash, [0u8; 64]);

        // Decrypt and verify data
        let decrypted =
            hybrid_decrypt(&private_key, genesis.block_data).expect("Failed to decrypt block data");
        assert_eq!(decrypted, block_data);

        assert_ne!(genesis.block_hash, [0u8; 64]); // Hash should be computed
    }

    #[test]
    fn test_regular_block_creation() {
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");

        let parent_hash = [5u8; 64];
        let block_data = vec![10, 20, 30];

        let public_key_der = private_key
            .public_key_to_der()
            .expect("Failed to extract public key");
        let public_key =
            PKey::public_key_from_der(&public_key_der).expect("Failed to parse public key");
        let block = Block::new_regular_block(parent_hash, block_data.clone(), &public_key);

        assert_eq!(block.block_header.parent_hash, parent_hash);

        // Decrypt and verify data
        let decrypted = hybrid_decrypt(&private_key, block.block_data.clone())
            .expect("Failed to decrypt block data");
        assert_eq!(decrypted, block_data);

        assert_ne!(block.block_hash, [0u8; 64]);
    }

    #[test]
    fn test_header_bytes_serialization() {
        let (header, _) = BlockHeader::new([42u8; 64]);

        let bytes = header.get_bytes();

        // Should contain: uid(16) + version(4) + parent_hash(64) + timestamp(8) + nonce(8) = 100 bytes
        assert_eq!(bytes.len(), 100);

        // Verify parent_hash is in the serialized bytes
        assert!(bytes.windows(64).any(|window| window == &[42u8; 64]));
    }

    #[test]
    fn test_block_hash_computation() {
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");

        let block_data = vec![100, 101, 102];
        let public_key_der = private_key
            .public_key_to_der()
            .expect("Failed to extract public key");
        let public_key =
            PKey::public_key_from_der(&public_key_der).expect("Failed to parse public key");
        let block = Block::new_genesis_block(block_data, &public_key);

        // Recompute hash to verify it matches
        let computed_hash = block.block_header.generate_block_hash();

        assert_eq!(block.block_hash, computed_hash);
        assert_ne!(block.block_hash, [0u8; 64]); // Hash should not be all zeros
    }

    #[test]
    fn test_different_blocks_have_different_uids() {
        let (header1, _) = BlockHeader::new([0u8; 64]);
        let (header2, _) = BlockHeader::new([0u8; 64]);

        assert_ne!(header1.block_uid, header2.block_uid);
    }

    #[test]
    fn test_block_chain_linking() {
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");

        let public_key_der = private_key
            .public_key_to_der()
            .expect("Failed to extract public key");
        let public_key =
            PKey::public_key_from_der(&public_key_der).expect("Failed to parse public key");

        // Create genesis block
        let genesis = Block::new_genesis_block(vec![1, 2, 3], &public_key);

        // Create next block using genesis hash
        let block2 = Block::new_regular_block(genesis.block_hash, vec![4, 5, 6], &public_key);

        assert_eq!(block2.block_header.parent_hash, genesis.block_hash);

        // Create third block
        let block3 = Block::new_regular_block(block2.block_hash, vec![7, 8, 9], &public_key);

        assert_eq!(block3.block_header.parent_hash, block2.block_hash);
    }

    #[test]
    fn test_get_block_data() {
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");

        let original_data = vec![42, 100, 200, 255, 1, 2, 3];
        let public_key_der = private_key
            .public_key_to_der()
            .expect("Failed to extract public key");
        let public_key =
            PKey::public_key_from_der(&public_key_der).expect("Failed to parse public key");
        let block = Block::new_genesis_block(original_data.clone(), &public_key);

        // Use the static method to decrypt block data
        let decrypted_data =
            Block::get_block_data(block, &private_key).expect("Failed to decrypt block data");

        assert_eq!(decrypted_data, original_data);
    }

    #[test]
    fn test_get_block_data_regular_block() {
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");

        let original_data = b"This is secret blockchain transaction data".to_vec();
        let parent_hash = [99u8; 64];
        let public_key_der = private_key
            .public_key_to_der()
            .expect("Failed to extract public key");
        let public_key =
            PKey::public_key_from_der(&public_key_der).expect("Failed to parse public key");
        let block = Block::new_regular_block(parent_hash, original_data.clone(), &public_key);

        // Decrypt using static method
        let decrypted_data =
            Block::get_block_data(block, &private_key).expect("Failed to decrypt block data");

        assert_eq!(decrypted_data, original_data);
    }
}
