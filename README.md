# libblockchain

A generic, lightweight Rust library for creating and managing blockchain blocks with persistent RocksDB storage. This library provides core block structures and database-backed persistence while remaining agnostic to the actual data you store in blocks.

## Features

- **Data-agnostic**: Store any application-specific data in blocks (JSON, binary, custom formats)
- **Persistent storage**: RocksDB-backed blockchain persistence
- **Type-state pattern**: Compile-time enforcement of read-only vs read-write access
- **Automatic height management**: Heights assigned automatically for sequential block ordering
- **Block size limit**: 100MB maximum block size enforced
- **Auto-validation**: Automatic incremental validation on block insert
- **Validation cache**: Tracks last validated height for fast incremental validation
- **Iterator support**: Efficient block traversal with standard Rust iterator
- **Height-based indexing**: Efficient block lookup by sequential height
- **Configurable database**: Multiple RocksDB presets (high performance, high durability, read-only)
- **SHA-512 hashing**: 64-byte cryptographic hashes for block integrity
- **Chain validation**: Full or incremental validation with timestamp and signature checks

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
libblockchain = { git = "https://github.com/jessethepro/libblockchain.git" }
```

### Build Requirements

**Important**: This library compiles RocksDB and OpenSSL from source:
- **RocksDB**: Compiled with `mt_static` feature (static linking)
- **OpenSSL**: Compiled with `vendored` feature (builds from source)

The first build may take **5-10 minutes** due to C++ compilation. You'll need:
- C++ compiler (g++ or clang)
- CMake (for RocksDB)
- Standard build tools (make, etc.)

Subsequent builds are faster as dependencies are cached.

## Quick Start

```rust
use libblockchain::blockchain::open_read_write_chain;

// Create or open a blockchain
let chain = open_read_write_chain("./my_blockchain".into())?;

// Insert blocks (height auto-assigned, auto-validated, max 100MB)
chain.put_block(b"Genesis data".to_vec())?;
chain.put_block(b"Block 1 data".to_vec())?;
chain.put_block(b"Block 2 data".to_vec())?;

// Query blocks
let genesis = chain.get_block_by_height(0)?;
println!("Genesis data: {:?}", genesis.block_data());

// Get latest block
let count = chain.block_count()?;
if count > 0 {
    let latest = chain.get_block_by_height(count - 1)?;
    println!("Latest block data: {:?}", latest.block_data());
}

// Validate entire blockchain integrity
chain.validate()?;
println!("Blockchain has {} blocks and is valid!", count);
```

## Architecture

### Core Components

**Block Structures** ([src/block.rs](src/block.rs)):
- `BlockHeader`: Metadata (height, UUID, version, parent_hash, timestamp) - 100 bytes fixed
- `Block`: Complete block with header, SHA-512 hash, and data payload
- Height stored in header, assigned on insertion by counting existing blocks

**Blockchain Storage** ([src/blockchain.rs](src/blockchain.rs)):
- **Type-state pattern**: `OpenChain`, `ReadOnly`, `ReadWrite` for compile-time safety
- Two RocksDB column families: `blocks` and `signatures`
- Database is `DBWithThreadMode<SingleThreaded>` (not thread-safe)
- Helper functions: `open_read_only_chain()`, `open_read_write_chain()`

**Database Configuration** ([src/db_model.rs](src/db_model.rs)):
- Presets: `high_performance()`, `high_durability()`, `read_only()`
- Builder pattern for customization
- Defaults: 512MB block cache, 64MB write buffer, LZ4 compression

### Database Structure

The blockchain uses two RocksDB column families:
- **`blocks`**: Maps block height (u64) → Block data
- **`signatures`**: Maps block height (u64) → signature bytes

### Type-State Pattern

Compile-time enforcement prevents calling write methods on read-only chains:

```rust
use libblockchain::blockchain::{BlockChain, ReadOnly, ReadWrite};

// Read-only access
let ro_chain = BlockChain::<ReadOnly>::open_read_only(...)?;
let block = ro_chain.get_block_by_height(0)?;  // OK
// ro_chain.put_block(data)?;  // Compile error!

// Read-write access
let rw_chain = BlockChain::<ReadWrite>::open_read_write(...)?;
rw_chain.put_block(data)?;  // OK
```

## Usage Examples

### Opening a Blockchain

```rust
use libblockchain::blockchain::{BlockChain, OpenChain, open_read_write_chain, open_read_only_chain};

// Method 1: Using helper functions (recommended)
let chain = open_read_write_chain("./my_blockchain".into(), true)?;

// Method 2: Type-state pattern (more control)
let open_chain = BlockChain::<OpenChain>::open_or_create("./my_blockchain".into())?;
let rw_chain = BlockChain::<ReadWrite>::open_read_write(open_chain)?;

// Read-only access
let ro_chain = open_read_only_chain("./my_blockchain".into())?;
```

### Inserting Blocks

```rust
// Heights are assigned automatically (0, 1, 2, ...)
// Each block is auto-validated incrementally
// Maximum block size: 100MB
let height0 = chain.put_block(b"Genesis data".to_vec())?;
let height1 = chain.put_block(b"Block 1 data".to_vec())?;

println!("Inserted blocks at heights: {}, {}", height0, height1);

// Size limit enforcement
let large_data = vec![0u8; 101 * 1024 * 1024]; // 101MB
match chain.put_block(large_data) {
    Err(e) => println!("Rejected: {}", e), // "Block data exceeds maximum size"
    Ok(_) => unreachable!(),
}
```

### Iterating Over Blocks

```rust
// Use the iterator for efficient traversal
for block_result in chain.iter()? {
    let block = block_result?;
    println!("Block {}: {} bytes", block.height(), block.block_data().len());
}

// Iterator methods work too
let total_size: usize = chain.iter()?
    .map(|b| b.ok().map(|block| block.block_data().len()).unwrap_or(0))
    .sum();

println!("Total blockchain size: {} bytes", total_size);
```

### Querying Blocks

```rust
// By height
let block = chain.get_block_by_height(5)?;

// Access block fields
println!("Height: {}", block.height());
println!("Hash: {:?}", block.block_hash());
println!("Parent: {:?}", block.parent_hash());
println!("Data: {:?}", block.block_data());

// Get latest block
let count = chain.block_count()?;
if count > 0 {
    let latest = chain.get_block_by_height(count - 1)?;
}
```

### Iterating Over Blocks

```rust
// Manual iteration by height
let count = chain.block_count()?;
for height in 0..count {
    let block = chain.get_block_by_height(height)?;
    println!("Block {}: {:?}", height, block.block_hash());
}
```

### Storing Custom Data

```rust
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct Transaction {
    from: String,
    to: String,
    amount: u64,
}

let tx = Transaction {
    from: "Alice".to_string(),
    to: "Bob".to_string(),
    amount: 100,
};

// Serialize and insert
let data = serde_json::to_vec(&tx)?;
chain.put_block(data)?;

// Later, retrieve and deserialize
let count = chain.block_count()?;
let block = chain.get_block_by_height(count - 1)?;
let retrieved_tx: Transaction = serde_json::from_slice(&block.block_data())?;
```

### Custom Database Configuration

```rust
use libblockchain::db_model::{RocksDbModel, CompressionType};

// Use a preset
let db = RocksDbModel::high_performance("./fast_blockchain")
    .with_column_family("blocks")
    .with_column_family("signatures")
    .open()?;

// Fully customize
let db = RocksDbModel::new("./custom_blockchain")
    .with_block_cache_size_mb(2048)  // 2GB cache
    .with_write_buffer_size_mb(256)
    .with_compression(CompressionType::Zstd)
    .with_column_family("blocks")
    .with_column_family("signatures")
    .open()?;
```

### Block Validation

```rust
// Validate entire chain
chain.validate()?;
println!("Blockchain is valid!");

// validate() checks:
// - Heights are sequential (0, 1, 2, ...)
// - Genesis block has parent_hash = [0u8; 64]
// - Each block's parent_hash matches previous block's hash
// - Each block's hash is correctly computed
```

## API Reference

### `BlockChain<Mode>`

**Opening:**
- `BlockChain::<OpenChain>::open(path) -> Result<Self>`: Open existing blockchain
- `BlockChain::<OpenChain>::open_or_create(path) -> Result<Self>`: Create if missing
- `BlockChain::<ReadOnly>::open_read_only(OpenChain) -> Result<Self>`: Convert to read-only
- `BlockChain::<ReadWrite>::open_read_write(OpenChain) -> Result<Self>`: Convert to read-write

**Helper Functions:**
- `open_read_only_chain(path) -> Result<BlockChain<ReadOnly>>`
- `open_read_write_chain(path, create: bool) -> Result<BlockChain<ReadWrite>>`

**ReadOnly Operations:**
- `block_count() -> Result<u64>`: Total blocks in chain
- `get_block_by_height(height: u64) -> Result<Block>`: Retrieve block by height
- `get_signature_by_height(height: u64) -> Result<Vec<u8>>`: Retrieve signature
- `validate() -> Result<()>`: Verify entire chain integrity

**ReadWrite Operations (in addition to ReadOnly):**
- `put_block(data: Vec<u8>) -> Result<u64>`: Insert block, returns height
- `put_signature(height: u64, sig: Vec<u8>) -> Result<u64>`: Store signature
- `delete_last_block() -> Result<Option<u64>>`: Delete most recent block

### `Block`

**Creation:**
- `Block::new_genesis_block(data: Vec<u8>) -> Self`: Height 0, parent_hash = [0; 64]
- `Block::new_regular_block(height, parent_hash, data) -> Self`: Height > 0

**Accessors:**
- `height() -> u64`: Block height
- `block_hash() -> Vec<u8>`: 64-byte SHA-512 hash
- `parent_hash() -> Vec<u8>`: Parent block's hash
- `block_data() -> Vec<u8>`: Application data
- `block_uid() -> Vec<u8>`: 16-byte UUID
- `version() -> u32`: Block version (currently 1)
- `timestamp() -> SystemTime`: Creation timestamp

**Serialization:**
- `bytes() -> Vec<u8>`: Serialize to storage format
- `from_bytes(&[u8]) -> Result<Block>`: Deserialize from bytes

### `BlockHeader`

```rust
pub struct BlockHeader {
    height: u64,              // Block height (0 for genesis)
    block_uid: [u8; 16],     // UUID v4
    version: u32,             // Currently 1
    parent_hash: [u8; 64],   // SHA-512 of parent (zeros for genesis)
    timestamp: u64,           // Unix timestamp
}
```

Serialization: 100 bytes = height(8) + uid(16) + version(4) + parent_hash(64) + timestamp(8)

### `RocksDbModel`

**Presets:**
- `RocksDbModel::new(path)`: Default configuration
- `RocksDbModel::high_performance(path)`: Large cache, optimized for speed
- `RocksDbModel::high_durability(path)`: Sync writes, optimized for safety
- `RocksDbModel::read_only(path)`: Read-only access

**Builder Methods:**
- `with_block_cache_size_mb(mb)`: Cache size in MB (default: 512)
- `with_write_buffer_size_mb(mb)`: Write buffer in MB (default: 64)
- `with_compression(type)`: Compression algorithm (default: LZ4)
- `with_column_family(name)`: Add column family
- `open() -> Result<DB>`: Open the database

## Security Considerations

⚠️ **No Encryption**: This library stores all block data as plaintext in RocksDB.

- **Block Integrity**: SHA-512 hashes detect tampering
- **Chain Validation**: Parent hash links ensure sequential integrity
- **No Authentication**: Anyone with filesystem access can read/modify the database
- **No Encryption**: All `block_data` stored as plaintext
- **Application Responsibility**: Implement encryption at the application layer if needed

**Access Control**: RocksDB is an embedded database with no built-in access control. Security relies on:
- Operating system file permissions
- Application-level encryption (before calling `put_block()`)
- Process isolation

## Thread Safety

⚠️ **Single-Threaded**: The database is `DBWithThreadMode<SingleThreaded>` and **cannot be shared across threads**.

To use in multi-threaded applications, you would need to:
1. Change to `MultiThreaded` mode in the code
2. Add proper `Send`/`Sync` trait implementations
3. Handle concurrent access carefully

## Performance Tips

**Read Performance:**
- Use read-only mode when not modifying: `open_read_only_chain()`
- Adjust block cache size: `RocksDbModel::new(path).with_block_cache_size_mb(2048)`
- Sequential reads by height are efficient

**Write Performance:**
- Use `high_performance()` preset for write-heavy workloads
- Batch insertions if possible
- Database automatically flushes after each `put_block()`

**Storage:**
- Blocks stored with minimal overhead
- Compression enabled by default (LZ4)
- Use `CompressionType::Zstd` for better compression ratio

## What This Library Does NOT Include

This is a foundational library designed to be extended by applications. It does **not** include:

- Encryption/decryption (store encrypted data yourself if needed)
- Consensus mechanisms (PoW, PoS, PBFT, etc.)
- Networking/peer-to-peer communication
- Transaction validation logic
- Smart contract execution
- Merkle trees
- Mining algorithms
- Wallet management
- Cryptocurrency features

## Testing

```bash
cargo check    # Fast type checking
cargo build    # Full build (first time: 5-10 min)
cargo test     # Run tests (currently empty)
cargo clippy   # Lint checking
cargo doc --open  # View documentation
```

## Dependencies

Core dependencies:
- `rocksdb` 0.24: Embedded database with `mt_static` feature
- `openssl` 0.10: SHA-512 hashing with `vendored` feature
- `anyhow` 1.0: Error handling
- `uuid` 1.18: Block identifiers
- `serde` 1.0: Optional serialization support

See [Cargo.toml](Cargo.toml) for complete list.

## Contributing

Contributions are welcome! Please ensure:
- Code compiles with `cargo check`
- Clippy warnings addressed (`cargo clippy`)
- Data format agnosticism is maintained
- Documentation is updated

## License

MIT License - see [LICENSE](LICENSE) file for details.

Copyright (c) 2025 jessethepro

## Acknowledgments

Built with:
- [RocksDB](https://rocksdb.org/) - High-performance embedded database
- [OpenSSL](https://www.openssl.org/) - Cryptographic hashing
