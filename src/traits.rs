//! Core traits for the blockchain library
//!
//! These traits allow consumers to provide their own implementations
//! for cryptographic operations and other customizable behavior.

/// Trait for hashing operations in the blockchain.
///
/// Implement this trait to use custom hashing algorithms (SHA-256, SHA3, BLAKE3, etc.)
/// with the blockchain library.
///
/// # Examples
///
/// ```ignore
/// use sha2::{Sha256, Digest};
///
/// struct Sha256Hasher;
///
/// impl BlockHeaderHasher for Sha256Hasher {
///     fn hash(&self, data: &[u8]) -> Vec<u8> {
///         let mut hasher = Sha256::new();
///         hasher.update(data);
///         hasher.finalize().to_vec()
///     }
///
///     fn hash_size(&self) -> usize {
///         32 // SHA-256 produces 32-byte hashes
///     }
/// }
/// ```
pub trait BlockHeaderHasher {
    /// Compute the hash of the given data.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to hash
    ///
    /// # Returns
    ///
    /// A vector containing the hash bytes. The length should match `hash_size()`.
    fn hash(&self, data: &[u8]) -> Vec<u8>;

    /// Return the size of hashes produced by this hasher in bytes.
    ///
    /// This allows the library to validate hash lengths and allocate appropriately.
    fn hash_size(&self) -> usize;
}

/// Trait for creating a genesis block (the first block in a blockchain).
///
/// Genesis blocks have special properties:
/// - parent_hash is all zeros (no predecessor)
/// - Often used to establish initial state or configuration
pub trait GenesisBlock {
    /// Create a new genesis block with the given data.
    ///
    /// # Arguments
    ///
    /// * `hasher` - The hasher to use for computing the block hash
    /// * `block_data` - Application-specific data for the genesis block
    fn new_genesis<H: BlockHeaderHasher>(hasher: &H, block_data: Vec<u8>) -> Self;
}

/// Trait for creating a regular (non-genesis) block.
///
/// Regular blocks link to a parent block via parent_hash.
pub trait RegularBlock {
    /// Create a new block with the given parent hash and data.
    ///
    /// # Arguments
    ///
    /// * `hasher` - The hasher to use for computing the block hash
    /// * `parent_hash` - Hash of the previous block in the chain
    /// * `block_data` - Application-specific data for this block
    fn new_block<H: BlockHeaderHasher>(hasher: &H, parent_hash: [u8; 32], block_data: Vec<u8>) -> Self;
}
