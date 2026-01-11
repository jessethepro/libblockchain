# Copilot Instructions for libblockchain

## Project Overview
A **generic, data-agnostic blockchain library** with persistent storage, hybrid encryption, and secure key management. The library provides infrastructure for blockchain operations while remaining agnostic to payload content. Applications define what data goes in `block_data: Vec<u8>`.

**Tech Stack**: Rust (edition 2024), RocksDB (persistent storage), OpenSSL (cryptography), `secrecy` crate for key protection  
**Recent Activity**: Migrated from SledDB to RocksDB (December 2025), migrated from X509 certificates to direct PKey usage (December 2025), currently refactoring encryption API (January 2026)

**⚠️ CODE STATUS**: The `src/blockchain.rs` file currently has syntax errors and incomplete implementation. The struct `BlockChain` references `self.app_key` in `decrypt_block_data()` but this field is missing from the struct definition. The last stable API was `BlockChain::new(path, app_key: PKey<Private>)`.

**⚠️ Before making changes**: Run `cargo check` to see current compilation errors. The main issues are in [src/blockchain.rs](src/blockchain.rs) around line 183 (app_key reference) and line 258 (delete_latest_block match syntax).

## Architecture

### Core Components
- **[src/block.rs](src/block.rs)**: Block structures with SHA-512 hashing (64-byte hashes)
  - `BlockHeader`: Cryptographic data (height, UUID, version, parent_hash, timestamp) - 100 bytes fixed
  - `Block`: Complete block with header, hash, and encrypted data payload
  - Block height **IS in the header** - stored as part of block metadata, assigned on `put_block()`
  - Uses `openssl::hash::hash(MessageDigest::sha512(), ...)` for block hashing

- **[src/blockchain.rs](src/blockchain.rs)**: RocksDB-backed persistent storage with integrated encryption
  - Two RocksDB column families: `blocks` (height u64 → encrypted block), `signatures` (height u64 → signature)
  - Database wrapped in `Arc<DB>` for thread-safe sharing (planned - currently single-threaded)
  - **Hybrid encryption**: AES-256-GCM for block data, RSA-OAEP for key encapsulation
  - **Key protection**: Private keys stored in `SecretBox<Vec<u8>>` from `secrecy` crate, automatically zeroed on drop
  - Public key automatically extracted from private key DER data on initialization
  - Storage format: `[key_len(4)] || [RSA(AES_key)(var)] || [nonce(12)] || [tag(16)] || [data_len(4)] || [AES(Block)(var)]`

- **[src/db_model.rs](src/db_model.rs)**: RocksDB configuration with presets
  - Presets: `high_performance()`, `high_durability()`, `read_only()`
  - Builder methods: `.with_block_cache_size_mb()`, `.with_write_buffer_size_mb()`, `.with_compression()`, `.with_sync_writes()`, `.with_column_family()`
  - Default: 512MB block cache, 64MB write buffer, LZ4 compression, Zstd for bottommost level
  - Column families (tables): configure with `.with_column_family()` - must be added before `.open()`
  - Call `.open()` to create `rocksdb::DB` instance

### Key Design Decisions
- **Data-agnostic**: `block_data: Vec<u8>` - applications define the payload structure
- **Height-based storage**: Blocks stored by height (u64 as little-endian bytes) as primary key
- **Automatic height management**: Heights assigned on `put_block()` by counting existing blocks
- **Transparent encryption**: Encrypt on write, decrypt on read - users see plaintext `block_data`
- **Security by default**: All block data encrypted with unique AES-256-GCM keys per block
- **Key protection**: Keys wrapped in `secrecy::SecretBox` for automatic zeroing on drop
- **Column families**: RocksDB's equivalent of "tables" - accessed via `cf_handle()`
- **External dependencies**: `rocksdb` with `mt_static` feature for multi-threaded static linking, OpenSSL for crypto

## Data Types & Constants

```rust
// Block structure (src/block.rs)
const BLOCK_VERSION: u32 = 1;
const BLOCK_UID_SIZE: usize = 16;        // UUID bytes
const BLOCK_HASH_SIZE: usize = 64;       // SHA-512 hash
const BLOCK_HEADER_SIZE: usize = 100;    // height(8) + uid(16) + version(4) + parent(64) + timestamp(8)

// Encryption (src/blockchain.rs)
const AES_GCM_256_KEY_SIZE: usize = 32;  // 256-bit AES key
const AES_GCM_NONCE_SIZE: usize = 12;    // 96-bit nonce
const AES_GCM_TAG_SIZE: usize = 16;      // 128-bit auth tag
```

## Core API Methods

### BlockChain Operations
```rust
// Initialization
BlockChain::new(path, app_key: PKey<Private>)  // Opens/creates blockchain with OpenSSL private key

// Insertion & deletion
.put_block(data: Vec<u8>)                // Insert block with automatic height assignment
.put_signature(height, signature)        // Store signature for block at height
.delete_latest_block()                   // Delete most recent block (returns Option<u64>)

// Querying
.get_block_by_height(height: u64)        // Retrieve by height (0-indexed), automatically decrypted
.get_signature_by_height(height: u64)    // Retrieve signature for block
.get_max_height()                        // Get height of last block (or 0 for empty)
.block_count()                           // Total blocks in chain

// Validation & iteration
.validate()                              // Verify entire chain integrity (parent hashes)
.iter()                                  // Returns BlockIterator for sequential traversal
```

## Development Workflow

### Build & Test
```bash
cargo check                    # Fast type checking - USE FIRST to see current errors
cargo build                    # First build takes 5-10 min (compiles RocksDB + OpenSSL)
cargo test                     # Run unit tests (currently none exist)
cargo doc --open               # View documentation
cargo clippy                   # Lint checking (project uses clippy::unwrap_used & indexing_slicing warnings)
```

**⚠️ Current Build Status**: The project has active syntax/compilation errors in [src/blockchain.rs](src/blockchain.rs). Run `cargo check` to see:
- Missing `app_key` field in `BlockChain` struct (referenced at line 183)
- Syntax errors in `delete_latest_block()` match statement (line 258)
- Unclosed delimiter causing cascading errors

**Build Requirements**: Linux (for compilation), C++ compiler (g++/clang), CMake, make. RocksDB and OpenSSL compile from source via `vendored` and `mt_static` features.

**Clippy Configuration**: Project enforces `#![warn(clippy::unwrap_used)]` and `#![warn(clippy::indexing_slicing)]` - use proper error handling and bounds checking.

### Generating and Using Keys
```rust
use openssl::rsa::Rsa;
use openssl::pkey::PKey;
use libblockchain::blockchain::BlockChain;

// Generate RSA key pair
let rsa = Rsa::generate(4096)?;
let private_key = PKey::from_rsa(rsa)?;

// Create blockchain with the key
let chain = BlockChain::new("./my_blockchain", private_key)?;

// Insert encrypted blocks
chain.put_block(b"Genesis data".to_vec())?;
```

### Key Storage Patterns
```bash
# Generate key file (PEM format)
openssl genrsa -out private_key.pem 4096

# Load from PEM file in Rust
use openssl::pkey::PKey;
use std::fs;

let pem_data = fs::read("private_key.pem")?;
let private_key = PKey::private_key_from_pem(&pem_data)?;
let chain = BlockChain::new("./my_blockchain", private_key)?;
```

### Database Inspection
```rust
// RocksDB data stored at: <path> directory
// Use RocksDB CLI or Rust code to inspect:
use rocksdb::{DB, IteratorMode, Options};
let mut opts = Options::default();
opts.create_if_missing(false);
let db = DB::open_cf(&opts, "./my_blockchain", &["blocks", "signatures"])?;
let blocks_cf = db.cf_handle("blocks").unwrap();
let signatures_cf = db.cf_handle("signatures").unwrap();
```

## Code Conventions

### Serialization Format
```rust
// BlockHeader (100 bytes): height(8) || uid(16) || version(4) || parent_hash(64) || timestamp(8)
// Block: header(100) || block_hash(64) || data_len(4) || block_data(var)
// Stored (encrypted): key_len(4) || RSA(AES_key)(var) || nonce(12) || tag(16) || data_len(4) || AES(Block)(var)
```

### Error Handling
- Use `anyhow::Result<T>` for all fallible operations
- Add context with `.context("Description")` or `.with_context(|| format!("..."))`
- Database operations should flush after inserts to ensure durability
- Crypto errors propagate through `anyhow` with descriptive context
- **Never use `.unwrap()`** - project enables `clippy::unwrap_used` warnings
- Use `.ok_or_else(|| anyhow!(...))` for `Option` unwrapping
- Use `.expect()` only for infallible operations with clear justification comments

### When Adding Features

**Adding Block Fields:**
- Add to `BlockHeader` ONLY if cryptographically relevant (affects hash)
- Update `BLOCK_VERSION` constant for breaking changes
- Update `BlockHeader::bytes()` and `::new_from_bytes()` serialization
- Adjust `BLOCK_HEADER_SIZE` constant if size changes

**Cryptographic Changes:**
- SHA-512 hardcoded in `BlockHeader::new()` and `::generate_block_hash()`
- AES-256-GCM cipher fixed in `BlockChain::put_block()` and `::get_block_by_height()`
- RSA-OAEP with SHA-256 MGF1 for key encapsulation (see `hybrid_encrypt()`/`hybrid_decrypt()`)
- To make pluggable: extract to trait or strategy pattern

**Database Changes:**
- RocksDB configuration in [src/db_model.rs](src/db_model.rs) - use presets not raw `rocksdb::Options`
- Column families must be specified at database open time
- All operations require `cf_handle()` lookup for the target column family
- Use `Arc<DB>` wrapper for thread-safe database sharing

**Key Management Changes:**
- Keys passed directly to `BlockChain::new()` as `PKey<Private>`
- Private keys wrapped in `SecretBox` internally for automatic zeroing
- Public key extracted automatically from private key on initialization
- Supports both PEM and DER format keys via OpenSSL's `PKey` API

## Security Considerations
- **Memory protection**: Private keys stored in `SecretBox<Vec<u8>>` from `secrecy` crate, automatically zeroed on drop
- **Key encapsulation**: Each block gets unique AES key, RSA-OAEP encrypts the AES key
- **Authenticated encryption**: AES-GCM provides both confidentiality and integrity (AEAD)
- **Random nonces**: 96-bit nonces generated per block for semantic security
- **No key persistence**: Keys only in memory, never serialized to database
- **Application responsibility**: Secure key storage/loading is application's responsibility

## Common Pitfalls
- **Key lifetime**: Pass key by value to `new()` - it will be moved and stored internally
- **Key format**: OpenSSL's `PKey` accepts both PEM and DER - use appropriate `from_pem()` or `from_der()` method
- **SecretBox protection**: Private key wrapped in `SecretBox` - only exposed during encryption/decryption operations
- **Don't access `block_data` before decryption**: `BlockChain` methods handle encryption/decryption transparently
- **Don't modify height in `BlockHeader` manually**: Height is assigned automatically by `put_block()` based on block count
- **Parent hash validation**: Genesis block has `parent_hash = [0u8; 64]`, not empty slice or Option
- **Thread safety**: Database already wrapped in `Arc<DB>` for multi-threaded access
- **Column family handles**: Always check `cf_handle()` returns `Some` before using - panic if None
- **Iterator sizing**: RocksDB iterators return `Box<[u8]>`, not `&[u8]` - copy to fixed-size arrays
- **Edition 2024**: Cargo.toml uses `edition = "2024"` - may require nightly Rust or recent stable (1.85+)
- **No `get_latest_block()` method**: Use `get_block_by_height(get_max_height()?)` pattern

## Incomplete/Future Work
- **No integration tests**: `tests/` directory exists but is empty - add tests that use real encrypted blocks
- **No consensus mechanism**: PoW/PoS not implemented - library is purely for data persistence, not mining
- **No network layer**: Purely local storage, no P2P or synchronization
- **No block validation hooks**: Applications can't inject custom validation rules
- **No key rotation**: Once blockchain is created with a key, changing keys requires manual migration
- **Thread safety**: Database wrapped in Arc but struct not Send/Sync - needs review for multi-threaded use

## Quick Reference Examples

### Get Latest Block
```rust
// No direct .get_latest_block() method - use this pattern:
let max_height = chain.get_max_height()?;
if max_height > 0 {
    let latest = chain.get_block_by_height(max_height)?;
}
```

### Working with Column Families
```rust
// Always get CF handle before operations
let blocks_cf = db.cf_handle("blocks")
    .ok_or_else(|| anyhow!("Failed to get blocks column family"))?;

// Use the handle for all CF operations
db.put_cf(blocks_cf, key, value)?;
let result = db.get_cf(blocks_cf, key)?;
```

### Iteration Pattern
```rust
// Use the built-in iterator for sequential access
for block_result in chain.iter() {
    let block = block_result?; // Handle Result properly
    // Block data is already decrypted here
    println!("Height: {}, Data: {:?}", block.block_header.height, block.block_data);
}
```

### Complete Working Example
```rust
use libblockchain::blockchain::BlockChain;
use openssl::rsa::Rsa;
use openssl::pkey::PKey;

// Generate RSA key pair
let rsa = Rsa::generate(4096)?;
let private_key = PKey::from_rsa(rsa)?;

// Create blockchain (key is moved and protected internally)
let chain = BlockChain::new("./my_blockchain", private_key)?;

// Insert blocks (automatically encrypted)
chain.put_block(b"Genesis data".to_vec())?;
chain.put_block(b"Block 1 data".to_vec())?;

// Query and validate (automatically decrypted)
let genesis = chain.get_block_by_height(0)?;
chain.validate()?;
println!("Blockchain has {} blocks", chain.block_count()?);
```

## Documentation References
- **Example code**: [examples/read_key_from_process_keyring.rs](examples/read_key_from_process_keyring.rs) - demonstrates reading keys from kernel keyring (legacy example, not used by current API)
- **API documentation**: Run `cargo doc --open` for full API reference
- **Keyutils documentation**: [docs/keyutils-usage.md](docs/keyutils-usage.md) - comprehensive guide to `keyutils` crate (for reference, not currently used)
