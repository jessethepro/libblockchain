#![warn(clippy::unwrap_used)]
#![warn(clippy::indexing_slicing)]

//! A generic blockchain library for creating and managing blockchain blocks
//!
//! This library provides core blockchain primitives including:
//! - Block structures with SHA-512 cryptographic hashing
//! - Persistent storage using RocksDB
//! - Integrated hybrid RSA-OAEP + AES-256-GCM encryption
//! - Automatic height and parent relationship management
//! - Secure key storage in Linux kernel keyring via `keyutils`
//!
//! # Build Dependencies
//!
//! **Note**: This library compiles RocksDB and OpenSSL from source during the build process:
//! - **RocksDB**: Built with `mt_static` feature for multi-threaded static linking
//! - **OpenSSL**: Built with `vendored` feature to compile from source
//!
//! The first build may take several minutes due to C++ compilation. Subsequent builds
//! will be faster as dependencies are cached.
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
//! use keyutils::{Keyring, SpecialKeyring};
//!
//! # fn example() -> anyhow::Result<()> {
//! // Attach to the process keyring (keys must be pre-loaded)
//! let keyring = Keyring::attach(SpecialKeyring::Process)?;
//!
//! // Create blockchain using keys from the keyring
//! let chain = BlockChain::new("./my_blockchain", keyring, "my-app-key".to_string())?;
//!
//! // Insert blocks (automatically encrypted with AES-256-GCM + RSA-OAEP)
//! chain.put_block(b"My genesis data".to_vec())?;
//! chain.put_block(b"Second block data".to_vec())?;
//!
//! // Query blocks (automatically decrypted)
//! let genesis = chain.get_block_by_height(0)?;
//! let max_height = chain.get_max_height()?;
//! let latest = chain.get_block_by_height(max_height)?;
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
//! - **Kernel Keyring Storage**: Private keys stored in Linux kernel keyring, isolated from userspace
//! - **No Disk Storage**: Keys never written to disk, remain in kernel memory
//! - **Process Isolation**: Keys accessible only within the process keyring scope
//! - **Random Nonces**: Unique encryption per block ensures semantic security
//!
//! # Design Decisions
//!
//! - **Data-agnostic**: Block data is `Vec<u8>` - applications define the payload structure
//! - **Height-based storage**: Blocks keyed directly by height for efficient sequential access
//! - **Automatic height management**: Heights assigned automatically and stored in BlockHeader
//! - **Thread-safe**: RocksDB Arc-wrapped database with internal locking
//! - **Integrated encryption**: Encryption/decryption happens transparently in blockchain layer
//! - **Native RocksDB iteration**: Efficient block traversal using RocksDB's iterator
//!

pub mod block;
pub mod blockchain;
pub mod db_model;

// Re-export uuid for convenience
pub use uuid;
