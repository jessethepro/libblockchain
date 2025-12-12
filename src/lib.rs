//! A generic blockchain library for creating and managing blockchain blocks
//!
//! This library provides core blockchain primitives including:
//! - Block structures with SHA-512 cryptographic hashing
//! - Persistent storage using RocksDB
//! - Integrated hybrid RSA-OAEP + AES-256-GCM encryption
//! - Automatic height and parent relationship management
//! - Interactive password prompting for encrypted private keys
//!
//! # Architecture
//!
//! The library is designed to be data-agnostic - the actual payload stored in blocks
//! is application-specific. This library provides the infrastructure for:
//! - Creating blocks with proper cryptographic linking
//! - Storing blocks persistently with automatic encryption/decryption
//! - Securing data with hybrid encryption (AES-256-GCM + RSA-OAEP)
//! - Querying blocks by height or UUID
//! - Validating blockchain integrity
//!
//! # Core Components
//!
//! - [`block`]: Block and BlockHeader structures with SHA-512 hashing
//! - [`blockchain`]: Persistent blockchain storage with integrated encryption
//! - [`db_model`]: RocksDB configuration and presets
//!
//! # Example
//!
//! ```no_run
//! use libblockchain::blockchain::BlockChain;
//!
//! # fn example() -> anyhow::Result<()> {
//! // Create a blockchain with private key (prompts for password if encrypted)
//! let chain = BlockChain::new("./my_blockchain", "./app_private_key.pem")?;
//!
//! // Insert blocks (automatically encrypted with AES-256-GCM + RSA-OAEP)
//! chain.put_block(b"My genesis data".to_vec())?;
//! chain.put_block(b"Second block data".to_vec())?;
//!
//! // Query blocks (automatically decrypted)
//! let genesis = chain.get_block_by_height(0)?;
//! let latest = chain.get_latest_block()?;
//!
//! // Access decrypted data directly
//! println!("Genesis data: {:?}", String::from_utf8_lossy(&genesis.block_data));
//!
//! // Iterate over all blocks
//! for block_result in chain.iter() {
//!     let block = block_result?;
//!     println!("Block hash: {:?}", block.block_hash);
//! }
//!
//! // Validate blockchain integrity
//! chain.validate()?;
//! # Ok(())
//! # }
//! ```
//!
//! # Security Features
//!
//! - **Hybrid Encryption**: AES-256-GCM for data encryption, RSA-OAEP for key encapsulation
//! - **Authenticated Encryption**: AES-GCM provides both confidentiality and integrity
//! - **Secure Key Storage**: Private keys protected using `secrecy` crate with automatic zeroing
//! - **Interactive Security**: Password prompting for encrypted private keys via `rpassword`
//! - **Random Nonces**: Unique encryption per block ensures semantic security
//!
//! # Design Decisions
//!
//! - **Data-agnostic**: Block data is `Vec<u8>` - applications define the payload structure
//! - **UUID-based storage**: Blocks stored by UUID, with separate height index
//! - **Automatic height management**: Heights assigned automatically on insertion
//! - **Thread-safe**: Mutex-protected height counter for concurrent access
//! - **Integrated encryption**: Encryption/decryption happens transparently in blockchain layer
//!

pub mod block;
pub mod blockchain;
pub mod db_model;

// Re-export uuid for convenience
pub use uuid;
