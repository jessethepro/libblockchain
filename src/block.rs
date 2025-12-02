//! Block structure for a blockchain implementation.
//!
//! Each block contains one block transaction and maintains the blockchain integrity
//! through cryptographic hashing and linking to previous blocks.

pub const BLOCK_VERSION: u32 = 1;
use crate::hybrid_encryption::hybrid_encrypt_to_bytes;
use libcertcrypto::CertificateTools;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;

/// Core header for a block in a blockchain.
/// This struct contains only cryptographically relevant data for hash calculations.
/// Block height is handled separately as database metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    /// Block Unique Identifier
    pub block_uid: uuid::Bytes,

    /// Header version to support upgrades.
    pub version: u32,

    /// Hash of the parent block (previous block).
    pub parent_hash: [u8; 32],

    /// Timestamp of block creation (UNIX epoch seconds).
    pub timestamp: u64,

    /// Nonce for proof-of-work or other consensus algorithms.
    pub nonce: u64,
}

impl BlockHeader {
    /// Create a fully constructed new header convenience constructor.
    /// Note: block_height is handled separately as database metadata.
    pub fn new(parent_hash: [u8; 32]) -> (Self, [u8; 32]) {
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
        let block_hash = header.generate_block_hash();
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

    pub fn generate_block_hash(&self) -> [u8; 32] {
        let header_bytes = self.get_bytes();
        let hash_vec =
            CertificateTools::hash_sha256(&header_bytes).expect("SHA-256 hashing failed");
        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&hash_vec[..32]);
        block_hash
    }
}

/// Represents a block in the blockchain
#[derive(Debug, Clone)]
pub struct Block {
    /// Block Header (cryptographically relevant data only)
    pub block_header: BlockHeader,

    /// This block's cryptographic hash (serialized header + block_data)
    pub block_hash: [u8; 32],

    /// Application-specific block data (opaque to this library)
    pub block_data: Vec<u8>,
}

impl Block {
    /// Regular constructor for Block
    pub fn new_regular_block(parent_hash: [u8; 32], block_data: Vec<u8>, app_cert: X509) -> Self {
        let encrypted_data =
            hybrid_encrypt_to_bytes(&app_cert, &block_data).expect("Failed to encrypt block data");
        let (header, block_hash) = BlockHeader::new(parent_hash);
        Self {
            block_header: header,
            block_hash: block_hash,
            block_data: encrypted_data,
        }
    }
    /// Genesis block constructor
    pub fn new_genesis_block(block_data: Vec<u8>, app_cert: X509) -> Self {
        let encrypted_data =
            hybrid_encrypt_to_bytes(&app_cert, &block_data).expect("Failed to encrypt block data");
        let (header, block_hash) = BlockHeader::new([0u8; 32]);
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
    pub fn get_block_data(block: Block, private_key: &PKey<Private>) -> anyhow::Result<Vec<u8>> {
        use crate::hybrid_encryption::hybrid_decrypt_from_bytes;
        hybrid_decrypt_from_bytes(private_key, &block.block_data)
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

pub fn deserialize_block(data: &[u8]) -> Option<Block> {
    if data.len() < 68 + 32 + 4 {
        return None; // Not enough data for header, hash, and length
    }

    // Deserialize header
    let block_uid = {
        let mut uid = [0u8; 16];
        uid.copy_from_slice(&data[0..16]);
        uid
    };
    let version = u32::from_le_bytes(data[16..20].try_into().unwrap());
    let parent_hash = {
        let mut phash = [0u8; 32];
        phash.copy_from_slice(&data[20..52]);
        phash
    };
    let timestamp = u64::from_le_bytes(data[52..60].try_into().unwrap());
    let nonce = u64::from_le_bytes(data[60..68].try_into().unwrap());
    let header = BlockHeader {
        block_uid,
        version,
        parent_hash,
        timestamp,
        nonce,
    };

    // Deserialize block hash
    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(&data[68..100]);

    // Deserialize block data length
    let data_len = u32::from_le_bytes(data[100..104].try_into().unwrap()) as usize;

    if data.len() < 104 + data_len {
        return None; // Not enough data for block data
    }

    // Deserialize block data
    let block_data = data[104..104 + data_len].to_vec();

    Some(Block {
        block_header: header,
        block_hash,
        block_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid_encryption::hybrid_decrypt_from_bytes;
    use anyhow::{Result, anyhow};
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::pkey::{PKey, Private};
    use openssl::rsa::Rsa;
    use openssl::x509::{X509Builder, X509NameBuilder};

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

    /// Generate a test X509 certificate for testing
    fn generate_test_cert(private_key: &PKey<Private>) -> Result<X509> {
        let mut builder =
            X509Builder::new().map_err(|e| anyhow!("Failed to create X509 builder: {}", e))?;

        // Set version to X509v3
        builder
            .set_version(2)
            .map_err(|e| anyhow!("Failed to set version: {}", e))?;

        // Generate serial number
        let serial = BigNum::from_u32(1).map_err(|e| anyhow!("Failed to create serial: {}", e))?;
        let serial = serial
            .to_asn1_integer()
            .map_err(|e| anyhow!("Failed to convert serial: {}", e))?;
        builder
            .set_serial_number(&serial)
            .map_err(|e| anyhow!("Failed to set serial: {}", e))?;

        // Set subject name
        let mut name_builder =
            X509NameBuilder::new().map_err(|e| anyhow!("Failed to create name builder: {}", e))?;
        name_builder
            .append_entry_by_text("CN", "Test Certificate")
            .map_err(|e| anyhow!("Failed to set CN: {}", e))?;
        let name = name_builder.build();
        builder
            .set_subject_name(&name)
            .map_err(|e| anyhow!("Failed to set subject: {}", e))?;
        builder
            .set_issuer_name(&name)
            .map_err(|e| anyhow!("Failed to set issuer: {}", e))?;

        // Set validity period
        let not_before = Asn1Time::days_from_now(0)
            .map_err(|e| anyhow!("Failed to create not_before: {}", e))?;
        let not_after = Asn1Time::days_from_now(365)
            .map_err(|e| anyhow!("Failed to create not_after: {}", e))?;
        builder
            .set_not_before(&not_before)
            .map_err(|e| anyhow!("Failed to set not_before: {}", e))?;
        builder
            .set_not_after(&not_after)
            .map_err(|e| anyhow!("Failed to set not_after: {}", e))?;

        // Set public key
        builder
            .set_pubkey(private_key)
            .map_err(|e| anyhow!("Failed to set public key: {}", e))?;

        // Sign the certificate
        builder
            .sign(private_key, MessageDigest::sha256())
            .map_err(|e| anyhow!("Failed to sign certificate: {}", e))?;

        Ok(builder.build())
    }

    #[test]
    fn test_block_header_creation() {
        let parent_hash = [1u8; 32];
        let (header, block_hash) = BlockHeader::new(parent_hash);

        assert_eq!(header.version, BLOCK_VERSION);
        assert_eq!(header.parent_hash, parent_hash);
        assert!(header.timestamp > 0);
        assert_eq!(header.block_uid.len(), 16); // UUID is 16 bytes
        assert_ne!(block_hash, [0u8; 32]); // Hash should be generated
    }

    #[test]
    fn test_genesis_block_has_zero_parent_hash() {
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let cert = generate_test_cert(&private_key).expect("Failed to generate certificate");

        let block_data = vec![1, 2, 3, 4];
        let genesis = Block::new_genesis_block(block_data.clone(), cert);

        assert_eq!(genesis.block_header.parent_hash, [0u8; 32]);

        // Decrypt and verify data
        let decrypted = hybrid_decrypt_from_bytes(&private_key, &genesis.block_data)
            .expect("Failed to decrypt block data");
        assert_eq!(decrypted, block_data);

        assert_ne!(genesis.block_hash, [0u8; 32]); // Hash should be computed
    }

    #[test]
    fn test_regular_block_creation() {
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let cert = generate_test_cert(&private_key).expect("Failed to generate certificate");

        let parent_hash = [5u8; 32];
        let block_data = vec![10, 20, 30];

        let block = Block::new_regular_block(parent_hash, block_data.clone(), cert);

        assert_eq!(block.block_header.parent_hash, parent_hash);

        // Decrypt and verify data
        let decrypted = hybrid_decrypt_from_bytes(&private_key, &block.block_data)
            .expect("Failed to decrypt block data");
        assert_eq!(decrypted, block_data);

        assert_ne!(block.block_hash, [0u8; 32]);
    }

    #[test]
    fn test_header_bytes_serialization() {
        let (header, _) = BlockHeader::new([42u8; 32]);

        let bytes = header.get_bytes();

        // Should contain: uid(16) + version(4) + parent_hash(32) + timestamp(8) + nonce(8) = 68 bytes
        assert_eq!(bytes.len(), 68);

        // Verify parent_hash is in the serialized bytes
        assert!(bytes.windows(32).any(|window| window == &[42u8; 32]));
    }

    #[test]
    fn test_block_hash_computation() {
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let cert = generate_test_cert(&private_key).expect("Failed to generate certificate");

        let block_data = vec![100, 101, 102];
        let block = Block::new_genesis_block(block_data, cert);

        // Recompute hash to verify it matches
        let computed_hash = block.block_header.generate_block_hash();

        assert_eq!(block.block_hash, computed_hash);
    }

    #[test]
    fn test_different_blocks_have_different_uids() {
        let (header1, _) = BlockHeader::new([0u8; 32]);
        let (header2, _) = BlockHeader::new([0u8; 32]);

        assert_ne!(header1.block_uid, header2.block_uid);
    }

    #[test]
    fn test_block_chain_linking() {
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let cert = generate_test_cert(&private_key).expect("Failed to generate certificate");

        // Create genesis block
        let genesis = Block::new_genesis_block(vec![1, 2, 3], cert.clone());

        // Create next block using genesis hash
        let block2 = Block::new_regular_block(genesis.block_hash, vec![4, 5, 6], cert.clone());

        assert_eq!(block2.block_header.parent_hash, genesis.block_hash);

        // Create third block
        let block3 = Block::new_regular_block(block2.block_hash, vec![7, 8, 9], cert);

        assert_eq!(block3.block_header.parent_hash, block2.block_hash);
    }

    #[test]
    fn test_get_block_data() {
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let cert = generate_test_cert(&private_key).expect("Failed to generate certificate");

        let original_data = vec![42, 100, 200, 255, 1, 2, 3];
        let block = Block::new_genesis_block(original_data.clone(), cert);

        // Use the static method to decrypt block data
        let decrypted_data =
            Block::get_block_data(block, &private_key).expect("Failed to decrypt block data");

        assert_eq!(decrypted_data, original_data);
    }

    #[test]
    fn test_get_block_data_regular_block() {
        let private_key = generate_rsa_keypair(2048).expect("Failed to generate key");
        let cert = generate_test_cert(&private_key).expect("Failed to generate certificate");

        let original_data = b"This is secret blockchain transaction data".to_vec();
        let parent_hash = [99u8; 32];
        let block = Block::new_regular_block(parent_hash, original_data.clone(), cert);

        // Decrypt using static method
        let decrypted_data =
            Block::get_block_data(block, &private_key).expect("Failed to decrypt block data");

        assert_eq!(decrypted_data, original_data);
    }
}
