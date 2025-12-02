//! A generic blockchain library for creating and managing blockchain blocks
//!
//! This library provides core blockchain primitives including:
//! - Block structures with cryptographic hashing
//! - Persistent storage using SledDB
//! - Hybrid RSA+AES encryption for block data
//! - Automatic height and parent relationship management
//!
//! # Architecture
//!
//! The library is designed to be data-agnostic - the actual payload stored in blocks
//! is application-specific. This library provides the infrastructure for:
//! - Creating blocks with proper cryptographic linking
//! - Storing blocks persistently
//! - Encrypting block data
//! - Querying blocks by height or UUID
//!
//! # Core Components
//!
//! - [`block`]: Block and BlockHeader structures with hashing
//! - [`blockchain`]: Persistent blockchain storage with SledDB
//! - [`hybrid_encryption`]: RSA+AES hybrid encryption
//! - [`db_model`]: SledDB configuration and presets
//!
//! # Example
//!
//! ```no_run
//! use libblockchain::blockchain::BlockChain;
//! # use openssl::x509::X509;
//!
//! # fn example() -> anyhow::Result<()> {
//! // Create a blockchain
//! let chain = BlockChain::new("./my_blockchain")?;
//!
//! // Insert blocks (certificate needed for encryption)
//! # let cert: X509 = unsafe { std::mem::zeroed() };
//! chain.insert_block(b"My genesis data".to_vec(), cert.clone())?;
//! chain.insert_block(b"Second block data".to_vec(), cert)?;
//!
//! // Query blocks
//! let genesis = chain.get_block_by_height(0)?.unwrap();
//! let latest = chain.get_latest_block()?.unwrap();
//!
//! // Iterate over all blocks
//! for block_result in chain.iter() {
//!     let block = block_result?;
//!     println!("Block at height has hash: {:?}", block.block_hash);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Design Decisions
//!
//! - **Data-agnostic**: Block data is `Vec<u8>` - applications define the payload structure
//! - **UUID-based storage**: Blocks stored by UUID, with separate height index
//! - **Automatic height management**: Heights assigned automatically on insertion
//! - **Thread-safe**: Mutex-protected height counter for concurrent access
//!

pub mod block;
pub mod blockchain;
pub mod hybrid_encryption;
pub mod db_model;

// Re-export uuid for convenience
pub use uuid;

// Re-export CertificateTools from libcertcrypto
pub use libcertcrypto::CertificateTools;
