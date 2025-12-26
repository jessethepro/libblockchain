# Copilot Instructions for libblockchain

## Project Overview
A **generic, data-agnostic blockchain library** with persistent storage, hybrid encryption, and secure key management. The library provides infrastructure for blockchain operations while remaining agnostic to payload content. Applications define what data goes in `block_data: Vec<u8>`.

**Tech Stack**: Rust (edition 2024), RocksDB (persistent storage), OpenSSL (cryptography), Linux kernel keyring via `keyutils` crate  
**Recent Activity**: Migrated from PEM file-based keys to Linux kernel keyring (December 2025), successfully migrated from SledDB to RocksDB (December 2025)

**⚠️ Critical API Change**: `BlockChain::new()` now takes `keyutils::Keyring`, NOT `PKey<Private>` or file paths. Keys must be loaded into the Linux kernel keyring before blockchain initialization.

## Architecture

### Core Components
- **[src/block.rs](src/block.rs)**: Block structures with SHA-512 hashing (64-byte hashes)
  - `BlockHeader`: Cryptographic data (height, UUID, version, parent_hash, timestamp) - 100 bytes fixed
  - `Block`: Complete block with header, hash, and encrypted data payload
  - Block height **IS in the header** - stored as part of block metadata, assigned on `put_block()`
  - Uses `openssl::hash::hash(MessageDigest::sha512(), ...)` for block hashing

- **[src/blockchain.rs](src/blockchain.rs)**: RocksDB-backed persistent storage with integrated encryption
  - Two RocksDB column families: `blocks` (height u64 → encrypted block), `signatures` (height u64 → signature)
  - Database wrapped in `Arc<DB>` for thread-safe sharing
  - **Hybrid encryption**: AES-256-GCM for block data, RSA-OAEP for key encapsulation
  - **Kernel keyring integration**: Reads private keys from Linux kernel keyring using `keyutils` crate
  - Searches for key named `"root-key"` in the process keyring (hardcoded in `BlockChain::new()`)
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
- **Kernel keyring storage**: Private keys stored in Linux kernel keyring, isolated from userspace, never written to disk
- **Column families**: RocksDB's equivalent of "tables" - accessed via `cf_handle()`
- **External dependencies**: `rocksdb` with `mt_static` feature for multi-threaded static linking, OpenSSL for crypto, `keyutils` for kernel keyring

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
// Initialization (USES KERNEL KEYRING)
BlockChain::new(path, keyring: Keyring)  // Opens/creates blockchain, reads "root-key" from keyring

// Insertion & deletion
.put_block(data: Vec<u8>)                // Insert block with automatic height assignment
.put_signature(height, signature)        // Store signature for block at height
.delete_latest_block()                   // Delete most recent block (returns Option<u64>)

// Querying
.get_block_by_height(height: u64)        // Retrieve by height (0-indexed), automatically decrypted
.get_signature_by_height(height: u64)    // Retrieve signature for block
.get_max_height()                        // Get height of last block (or 0 for empty)
.block_count()                           // Total blocks in chain

// Mode switching
.into_read_only()                        // Convert to read-only (preserves keyring reference)
.into_read_write()                       // Convert back to read-write mode

// Validation & iteration
.validate()                              // Verify entire chain integrity (parent hashes)
.iter()                                  // Returns BlockIterator for sequential traversal
```

## Development Workflow

### Build & Test
```bash
cargo build                    # First build takes 5-10 min (compiles RocksDB + OpenSSL)
cargo test                     # Run unit tests (currently none exist)
cargo doc --open               # View documentation
cargo check                    # Fast type checking
cargo clippy                   # Lint checking (project uses clippy::unwrap_used & indexing_slicing warnings)
```

**Build Requirements**: Linux kernel 3.10+ (for keyring), C++ compiler (g++/clang), CMake, make. RocksDB and OpenSSL compile from source via `vendored` and `mt_static` features.

**Clippy Configuration**: Project enforces `#![warn(clippy::unwrap_used)]` and `#![warn(clippy::indexing_slicing)]` - use proper error handling and bounds checking.

### Working with Linux Kernel Keyring
The library requires keys to be pre-loaded into the Linux kernel keyring. **The blockchain searches for a key named `"root-key"`** (hardcoded in `src/blockchain.rs` line 121).

#### Generate and Load Keys
```bash
# Generate RSA private key (4096-bit recommended)
openssl genrsa 4096 > private_key.pem

# Convert to DER format (required for keyring)
openssl rsa -in private_key.pem -outform DER -out private_key.der

# Load into process keyring (@p) with name "root-key"
keyctl padd user root-key @p < private_key.der

# Verify key is loaded
keyctl show @p

# List all keys in process keyring
keyctl list @p
```

#### Load Keys from Rust
```rust
use keyutils::{Keyring, SpecialKeyring};
use keyutils::keytypes::user::User;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;

// Generate key in Rust
let rsa = Rsa::generate(4096)?;
let private_key = PKey::from_rsa(rsa)?;
let der = private_key.private_key_to_der()?;

// Add to process keyring with name "root-key"
let mut keyring = Keyring::attach_or_create(SpecialKeyring::Process)?;
keyring.add_key::<User, _, _>("root-key", &der)?;

// Then create blockchain
let chain = BlockChain::new("./my_blockchain", keyring)?;
```

#### Read Key from Keyring (for debugging)
```rust
use keyutils::{Keyring, SpecialKeyring};
use keyutils::keytypes::user::User;

let keyring = Keyring::attach(SpecialKeyring::Process)?;
let key = keyring.search_for_key::<User, _, _>("root-key", None)?;
let key_data: Vec<u8> = key.read()?;  // DER-encoded private key
```

**Important**: The key name `"root-key"` is hardcoded in `BlockChain::new()`. To use a different name, modify line 121 in [src/blockchain.rs](src/blockchain.rs).

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

**Keyring Changes:**
- Key name `"root-key"` is hardcoded in [src/blockchain.rs](src/blockchain.rs) line 121 and 348
- Uses `SpecialKeyring::Process` for process-local key isolation
- Keys must be `user` type (via `keyutils::keytypes::user::User`)
- DER format required (not PEM) - use `PKey::private_key_to_der()` or `openssl rsa -outform DER`

## Security Considerations
- **Kernel-level isolation**: Private keys stored in Linux kernel keyring, isolated from userspace memory dumps
- **No disk persistence**: Keys remain in kernel memory, never written to disk
- **Process isolation**: Keys in process keyring (@p) are accessible only within the process
- **Key encapsulation**: Each block gets unique AES key, RSA-OAEP encrypts the AES key
- **Authenticated encryption**: AES-GCM provides both confidentiality and integrity (AEAD)
- **Memory zeroing**: Key data is Vec<u8> from keyring - no automatic zeroing on drop (kernel manages this)

## Common Pitfalls
- **Hardcoded key name**: `BlockChain::new()` searches for `"root-key"` - if you use a different name, blockchain initialization will fail
- **DER format required**: Keyring expects DER-encoded keys, not PEM. Convert with `openssl rsa -outform DER`
- **Process keyring scope**: Keys added to process keyring (@p) only exist within that process and its children
- **Key must exist before `new()`**: Unlike old PEM approach, you can't pass the key directly - must pre-load into keyring
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
- **Hardcoded key name**: Key name `"root-key"` should be configurable via constructor parameter
- **No key rotation**: Once blockchain is created with a key, changing keys requires manual migration

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
use keyutils::{Keyring, SpecialKeyring};
use keyutils::keytypes::user::User;
use openssl::rsa::Rsa;
use openssl::pkey::PKey;

// Generate and load key
let rsa = Rsa::generate(4096)?;
let private_key = PKey::from_rsa(rsa)?;
let der = private_key.private_key_to_der()?;

let mut keyring = Keyring::attach_or_create(SpecialKeyring::Process)?;
keyring.add_key::<User, _, _>("root-key", &der)?;

// Create blockchain
let chain = BlockChain::new("./my_blockchain", keyring)?;

// Insert blocks
chain.put_block(b"Genesis data".to_vec())?;
chain.put_block(b"Block 1 data".to_vec())?;

// Query and validate
let genesis = chain.get_block_by_height(0)?;
chain.validate()?;
println!("Blockchain has {} blocks", chain.block_count()?);
```

## Documentation References
- **Keyring usage guide**: [docs/keyutils-usage.md](docs/keyutils-usage.md) - comprehensive guide to `keyutils` crate
- **Example code**: [examples/read_key_from_process_keyring.rs](examples/read_key_from_process_keyring.rs) - demonstrates reading keys from keyring
- **API documentation**: Run `cargo doc --open` for full API reference
