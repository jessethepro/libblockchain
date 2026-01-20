# Copilot Instructions for libblockchain

## Project Overview
A **generic, data-agnostic blockchain library** with persistent RocksDB storage. The library provides infrastructure for blockchain operations while remaining agnostic to payload content. Applications define what data goes in `block_data: Vec<u8>`.

**Tech Stack**: Rust (edition 2024), RocksDB (persistent storage), OpenSSL (SHA-512 hashing only)  
**Recent Activity**: Migrated from SledDB to RocksDB (December 2025), refactored to type-state pattern (January 2026)

**⚠️ DOCUMENTATION LAG**: README.md and lib.rs describe a keyutils/encryption API that **does not exist** in the code. The actual implementation is a pure storage layer with type-state pattern for read/write modes. Ignore encryption/keyutils references in docs.

**✅ Current Build Status**: `cargo check` passes. Code compiles successfully.

## Architecture

### Core Components

**src/block.rs**: Block structures with SHA-512 hashing (64-byte hashes)
- `BlockHeader`: Metadata (height, UUID, version, parent_hash, timestamp) - 100 bytes fixed format
- `Block`: Complete block with header, hash, and data payload (NO encryption in current impl)
- Block height stored in header, assigned on `put_block()` by counting existing blocks
- Hash computed: `SHA512(header_bytes || block_data)` using OpenSSL

**src/blockchain.rs**: RocksDB-backed storage with **type-state pattern**
- **Type states**: `OpenChain`, `ReadOnly`, `ReadWrite` - enforces read-only vs read-write at compile time
- Two RocksDB column families: `blocks` (height u64 → Block), `signatures` (height u64 → signature bytes)
- Database is `DBWithThreadMode<SingleThreaded>` - NOT thread-safe currently
- NO encryption - blocks stored as plaintext serialized bytes
- Typical workflow: `BlockChain::<OpenChain>::open(path)` → `.open_read_only()` or `.open_read_write()`
- Helper functions: `open_read_only_chain(path)`, `open_read_write_chain(path, create_if_missing)`

**src/db_model.rs**: RocksDB configuration builder
- Presets: `RocksDbModel::high_performance()`, `::high_durability()`, `::read_only()`
- Builder pattern: `.with_block_cache_size_mb()`, `.with_write_buffer_size_mb()`, `.with_compression()`, `.with_column_family()`
- Defaults: 512MB block cache, 64MB write buffer, LZ4 compression
- Column families must be added **before** `.open()` call

### Key Design Patterns

**Type-State Pattern**: Compile-time enforcement of read-only vs read-write access
```rust
// Can't call put_block() on ReadOnly - won't compile
let ro_chain = BlockChain::<ReadOnly>::open_read_only(...)?;
let block = ro_chain.get_block_by_height(0)?; // OK
// ro_chain.put_block(data)?; // Compile error - method doesn't exist

// ReadWrite has both read and write methods
let rw_chain = BlockChain::<ReadWrite>::open_read_write(...)?;
rw_chain.put_block(data)?; // OK
```

**Height-Based Indexing**: Blocks keyed by u64 height (as little-endian bytes)
- Height 0 = genesis block with `parent_hash = [0u8; 64]`
- New block height = current block count (auto-assigned in `put_block()`)
- No UUID-based lookups - only by sequential height

**Serialization Format**:
```rust
// BlockHeader (100 bytes): height(8) || uid(16) || version(4) || parent_hash(64) || timestamp(8)
// Block: header(100) || block_hash(64) || data_len(4) || block_data(variable)
```

## Core API Methods

### BlockChain Type-State API

```rust
// Opening a blockchain
BlockChain::<OpenChain>::open(path: PathBuf)           // Opens existing DB (errors if missing)
BlockChain::<OpenChain>::open_or_create(path: PathBuf) // Creates if missing

// Convert to specific mode
BlockChain::<ReadOnly>::open_read_only(OpenChain)      // Read-only access
BlockChain::<ReadWrite>::open_read_write(OpenChain)    // Read-write access

// Helper functions (combines above steps)
open_read_only_chain(path: PathBuf)                    // open() + open_read_only()
open_read_write_chain(path: PathBuf, create: bool)     // open_or_create() + open_read_write()
```

### ReadOnly Operations
```rust
.block_count()                          // Total blocks in chain
.get_block_by_height(height: u64)       // Retrieve block by height (0-indexed)
.get_signature_by_height(height: u64)   // Retrieve signature for block
.validate()                             // Verify entire chain integrity (parent hashes)
```

### ReadWrite Operations
```rust
.block_count()                          // Also available on ReadWrite
.get_block_by_height(height: u64)       // Also available on ReadWrite
.put_block(data: Vec<u8>) -> Result<u64>       // Insert block, returns height
.put_signature(height: u64, sig: Vec<u8>)      // Store signature
.delete_last_block() -> Result<Option<u64>>    // Delete most recent block
```

### Block Operations
```rust
// Creating blocks (usually done internally by put_block)
Block::new_genesis_block(data: Vec<u8>)                 // Height 0, parent_hash = [0; 64]
Block::new_regular_block(height, parent_hash, data)     // Height > 0

// Accessors
block.height() -> u64
block.block_hash() -> Vec<u8>      // 64-byte SHA-512 hash
block.parent_hash() -> Vec<u8>
block.block_data() -> Vec<u8>
block.bytes() -> Vec<u8>           // Serialize to storage format

// Deserialization
Block::from_bytes(&[u8]) -> Result<Block>
```

## Development Workflow

### Build & Test
```bash
cargo check                    # Fast type checking - use first to catch errors
cargo build                    # First build takes 5-10 min (compiles RocksDB + OpenSSL from source)
cargo test                     # No tests currently exist
cargo doc --open               # View documentation
cargo clippy                   # Lint checking
```

**Build Requirements**: Linux, C++ compiler (g++/clang), CMake, make. RocksDB and OpenSSL compile from source via `vendored` and `mt_static` features.

**Clippy Configuration**: Project enforces `#![warn(clippy::unwrap_used)]` and `#![warn(clippy::indexing_slicing)]` - use proper error handling and bounds checking.

### Basic Usage Pattern
```rust
use libblockchain::blockchain::{BlockChain, OpenChain, open_read_write_chain};

// Create or open blockchain
let chain = open_read_write_chain("./my_blockchain".into(), true)?;

// Insert blocks (height auto-assigned)
let height0 = chain.put_block(b"Genesis data".to_vec())?;
let height1 = chain.put_block(b"Block 1 data".to_vec())?;

// Query blocks
let block = chain.get_block_by_height(0)?;
println!("Block 0 data: {:?}", block.block_data());

// Validate chain integrity
chain.validate()?;
```

### Working with RocksDB Configuration
```rust
use libblockchain::db_model::RocksDbModel;

// Open with preset configurations
let open_chain = BlockChain::<OpenChain>::open(path)?;
// Internally uses RocksDbModel::new(path) or RocksDbModel::read_only(path)

// For custom DB config, modify db_model.rs presets
// or use builder methods in RocksDbModel
```

## Code Conventions

### Serialization Format
```rust
// BlockHeader (100 bytes): height(8) || uid(16) || version(4) || parent_hash(64) || timestamp(8)
// Block: header(100) || block_hash(64) || data_len(4) || block_data(variable)
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
- SHA-512 hardcoded in `Block::new_regular_block()` for computing block hash
- Hash computed: `SHA512(header_bytes || block_data)` using OpenSSL
- No encryption currently implemented - all data stored as plaintext
- To add encryption: would need to modify `put_block()` and `get_block_by_height()` methods

**Database Changes:**
- RocksDB configuration in src/db_model.rs - use presets not raw `rocksdb::Options`
- Column families must be specified at database open time
- All operations require `cf_handle()` lookup for the target column family

**Type-State Changes:**
- Use generic `Mode` parameter: `BlockChain<OpenChain>`, `BlockChain<ReadOnly>`, `BlockChain<ReadWrite>`
- ReadOnly and ReadWrite contain the actual database instance
- OpenChain is just a transition state for opening/creating the database
- Cannot convert from ReadWrite back to ReadOnly without reopening the database

## Security Considerations
**⚠️ NO ENCRYPTION CURRENTLY**: Despite docs mentioning encryption, the current implementation stores all data as plaintext.

- **Block integrity**: SHA-512 hashes ensure blocks haven't been tampered with
- **Chain validation**: `validate()` method checks parent hash links
- **No authentication**: Anyone with filesystem access can read/modify the database
- **No encryption**: All `block_data` stored as plaintext in RocksDB
- **Application responsibility**: If you need encryption, implement it at the application layer before calling `put_block()`

## Common Pitfalls
- **Don't modify height in `BlockHeader` manually**: Height is assigned automatically by `put_block()` based on block count
- **Parent hash validation**: Genesis block has `parent_hash = [0u8; 64]`, not empty slice or Option
- **Thread safety**: Database is `SingleThreaded` - NOT thread-safe, cannot share across threads
- **Column family handles**: Always check `cf_handle()` returns `Some` before using
- **Edition 2024**: Cargo.toml uses `edition = "2024"` - requires recent stable Rust (1.85+)
- **No `get_latest_block()` method**: Use `get_block_by_height(block_count() - 1)?` pattern
- **Type-state limitations**: Can't convert from ReadWrite back to ReadOnly without reopening
- **ReadWrite operations reopen database**: `block_count()` and `get_block_by_height()` on ReadWrite internally reopen as ReadOnly

## Incomplete/Future Work
- **No tests**: `tests/` directory exists but is empty - add integration tests
- **No encryption**: Despite docs mentioning it, current impl has NO encryption or key management
- **No consensus mechanism**: PoW/PoS not implemented - library is purely for data persistence
- **No network layer**: Purely local storage, no P2P or synchronization
- **No block validation hooks**: Applications can't inject custom validation rules
- **Thread safety**: Single-threaded database - needs `MultiThreaded` mode for concurrent access
- **No iterator**: No built-in iterator for traversing all blocks (despite example showing `.iter()`)

## Quick Reference Examples

### Get Latest Block
```rust
// No direct .get_latest_block() or .get_max_height() method - use block_count:
let count = chain.block_count()?;
if count > 0 {
    let latest = chain.get_block_by_height(count - 1)?;
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
// No built-in iterator - manually iterate by height
let count = chain.block_count()?;
for height in 0..count {
    let block = chain.get_block_by_height(height)?;
    println!("Height: {}, Data: {:?}", block.height(), block.block_data());
}
```

### Complete Working Example
```rust
use libblockchain::blockchain::open_read_write_chain;

// Create or open blockchain
let chain = open_read_write_chain("./my_blockchain".into(), true)?;

// Insert blocks (height auto-assigned)
chain.put_block(b"Genesis data".to_vec())?;
chain.put_block(b"Block 1 data".to_vec())?;

// Query blocks
let genesis = chain.get_block_by_height(0)?;
println!("Genesis data: {:?}", genesis.block_data());

// Validate chain integrity
chain.validate()?;
println!("Blockchain has {} blocks", chain.block_count()?);
```

## Documentation References
- **Example code**: examples/read_key_from_process_keyring.rs - demonstrates reading keys from kernel keyring (legacy example, not used by current API)
- **API documentation**: Run `cargo doc --open` for full API reference
- **Keyutils documentation**: docs/keyutils-usage.md - comprehensive guide to `keyutils` crate (for reference, not currently used)
