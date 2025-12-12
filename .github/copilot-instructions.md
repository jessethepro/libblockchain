# Copilot Instructions for libblockchain

## Project Overview
A **generic, data-agnostic blockchain library** with persistent storage, hybrid encryption, and secure key management. The library provides infrastructure for blockchain operations while remaining agnostic to payload content. Applications define what data goes in `block_data: Vec<u8>`.

**Recent Activity**: Successfully migrated from SledDB to RocksDB (December 2025).

## Architecture

### Core Components
- **[src/block.rs](src/block.rs)**: Block structures with SHA-512 hashing (64-byte hashes)
  - `BlockHeader`: Cryptographic data (UUID, version, parent_hash, timestamp, nonce) - 100 bytes fixed
  - `Block`: Complete block with header, hash, and encrypted data payload
  - Block height is **NOT in the header** - managed automatically by `BlockChain` as database metadata
  - Uses `openssl::hash::hash(MessageDigest::sha512(), ...)` for block hashing

- **[src/blockchain.rs](src/blockchain.rs)**: RocksDB-backed persistent storage with integrated encryption
  - Two RocksDB column families: `blocks` (UUID → block), `height` (u64 → UUID)
  - Mutex-protected `current_height` counter for thread-safe concurrent inserts
  - Database wrapped in `Arc<DB>` for thread-safe sharing
  - **Hybrid encryption**: AES-256-GCM for block data, RSA-OAEP for key encapsulation
  - Private keys wrapped in `SecretBox<SecurePrivateKey>` (implements `Zeroize`)
  - Interactive password prompting for encrypted PEM files via `rpassword`
  - Public key automatically extracted from private key on initialization
  - Storage format: `[key_len(4)] || [RSA(AES_key)(var)] || [nonce(12)] || [tag(16)] || [block_len(4)] || [AES(Block)(var)]`

- **[src/db_model.rs](src/db_model.rs)**: RocksDB configuration with presets
  - Presets: `high_performance()`, `high_durability()`, `read_only()`
  - Builder methods: `.with_block_cache_size_mb()`, `.with_write_buffer_size_mb()`, `.with_compression()`, `.with_sync_writes()`, `.with_column_family()`
  - Default: 512MB block cache, 64MB write buffer, LZ4 compression, Zstd for bottommost level
  - Column families (tables): configure with `.with_column_family()` - must be added before `.open()`
  - Call `.open()` to create `rocksdb::DB` instance

### Key Design Decisions
- **Data-agnostic**: `block_data: Vec<u8>` - applications define the payload structure
- **UUID-based storage**: Blocks stored by UUID (16 bytes) with separate height column family for sequential access
- **Automatic height management**: Heights assigned on `put_block()`, incremented atomically
- **Transparent encryption**: Encrypt on write, decrypt on read - users see plaintext `block_data`
- **Security by default**: All block data encrypted with unique AES-256-GCM keys per block
- **Column families**: RocksDB's equivalent of "tables" - accessed via `cf_handle()`
- **External dependencies**: `rocksdb` with `mt_static` feature for multi-threaded static linking, OpenSSL for crypto

## Data Types & Constants

```rust
// Block structure (src/block.rs)
const BLOCK_VERSION: u32 = 1;
const BLOCK_UID_SIZE: usize = 16;        // UUID bytes
const BLOCK_HASH_SIZE: usize = 64;       // SHA-512 hash
const BLOCK_HEADER_SIZE: usize = 100;    // uid(16) + version(4) + parent(64) + time(8) + nonce(8)

// Encryption (src/blockchain.rs)
const AES_GCM_256_KEY_SIZE: usize = 32;  // 256-bit AES key
const AES_GCM_NONCE_SIZE: usize = 12;    // 96-bit nonce
const AES_GCM_TAG_SIZE: usize = 16;      // 128-bit auth tag
```

## Core API Methods

### BlockChain Operations
```rust
// Initialization & insertion
BlockChain::new(path, private_key_path)  // Opens/creates blockchain, prompts for password
.put_block(data: Vec<u8>)                // Insert block with automatic height assignment

// Querying
.get_block_by_height(height: u64)        // Retrieve by height (0-indexed)
.get_block_by_uuid(&uuid)                // Retrieve by UUID, returns Option<Block>
.get_latest_block()                      // Get highest height block
.get_height()                            // Get current height (next to be assigned)
.block_count()                           // Total blocks in chain
.block_exists(&uuid)                     // Check UUID existence

// Validation & iteration
.validate()                              // Verify entire chain integrity (parent hashes)
.iter()                                  // Returns BlockIterator for sequential traversal
```

## Development Workflow

### Build & Test
```bash
cargo build                    # Compile library
cargo test                     # Run unit tests (db_model has tests)
cargo doc --open               # View documentation
cargo check                    # Fast type checking
```

### Testing Private Key Encryption
The library prompts for passwords at runtime. Generate test keys:
```bash
# Generate RSA key (4096-bit recommended)
openssl genrsa -aes256 -out test_key.pem 4096

# Or unencrypted for testing
openssl genrsa -out test_key_nopass.pem 4096
```

### Database Inspection
```rust
// RocksDB data stored at: <path> directory
// Use RocksDB CLI or Rust code to inspect:
use rocksdb::{DB, IteratorMode, Options};
let mut opts = Options::default();
opts.create_if_missing(false);
let db = DB::open_cf(&opts, "./my_blockchain", &["blocks", "height"])?;
let blocks_cf = db.cf_handle("blocks").unwrap();
let height_cf = db.cf_handle("height").unwrap();
```

## Code Conventions

### Serialization Format
```rust
// BlockHeader (100 bytes): uid(16) || version(4) || parent_hash(64) || timestamp(8) || nonce(8)
// Block: header(100) || block_hash(64) || data_len(4) || block_data(var)
// Stored (encrypted): key_len(4) || RSA(AES_key)(var) || nonce(12) || tag(16) || block_len(4) || AES(Block)(var)
```

### Error Handling
- Use `anyhow::Result<T>` for all fallible operations
- Add context with `.context("Description")` or `.with_context(|| format!("..."))`
- Database operations should flush after inserts to ensure durability
- Crypto errors propagate through `anyhow` with descriptive context

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

## Security Considerations
- **Private keys never logged**: `SecurePrivateKey` implements `Debug` as `<redacted>`
- **Memory zeroing**: Private key DER bytes zeroed on drop via `Zeroize` trait
- **Password input**: Uses `rpassword` to avoid echoing passwords to terminal
- **Key encapsulation**: Each block gets unique AES key, RSA-OAEP encrypts the AES key
- **Authenticated encryption**: AES-GCM provides both confidentiality and integrity (AEAD)

## Common Pitfalls
- **Don't access `block_data` before decryption**: `BlockChain` methods handle encryption/decryption transparently
- **Don't store height in `BlockHeader`**: Height is database metadata managed by `current_height` Mutex, NOT part of block structure
- **Don't call `Block::bytes()` on encrypted blocks**: Hashing happens in `BlockHeader` before encryption
- **Parent hash validation**: Genesis block has `parent_hash = [0u8; 64]`, not empty slice or Option
- **Thread safety**: Database already wrapped in `Arc<DB>`, `current_height` is Mutex-protected
- **Column family handles**: Always check `cf_handle()` returns `Some` before using - panic if None
- **Iterator sizing**: RocksDB iterators return `Box<[u8]>`, not `&[u8]` - copy to fixed-size arrays
- **Edition 2024**: Cargo.toml uses `edition = "2024"` - may require nightly Rust or recent stable (1.85+)
- **Password prompts**: `BlockChain::new()` calls `rpassword::prompt_password_stderr()` - cannot be automated in tests

## Incomplete/Future Work
- **No integration tests**: `tests/` directory exists but is empty - add tests that use real encrypted blocks
- **No consensus mechanism**: PoW/PoS not implemented - nonce field exists in BlockHeader but unused
- **No network layer**: Purely local storage, no P2P or synchronization
- **No block validation hooks**: Applications can't inject custom validation rules
- **Iterator limitations**: No reverse iteration, filtering, or seeking to specific heights
- **SledDB removed**: Migration to RocksDB complete, but no backward compatibility with Sled databases
- **No benchmark suite**: Consider adding criterion benchmarks for encryption/decryption performance
