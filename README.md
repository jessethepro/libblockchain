# libblockchain

A generic, lightweight Rust library for creating and managing blockchain blocks with persistent RocksDB storage. This library provides core block structures and database-backed persistence while remaining agnostic to the actual data you store in blocks.

Current API note: the blockchain layer exposes a single shared read/write handle. Open it with `open_chain()` or `BlockChain::open(...)`, and clone the handle to share it across threads.

## Features

- **Data-agnostic**: Store any application-specific data in blocks (JSON, binary, custom formats)
- **Persistent storage**: RocksDB-backed blockchain persistence
- **Automatic height management**: Heights assigned automatically for sequential block ordering
- **Block size limit**: 100MB maximum block size enforced
- **Auto-validation**: Automatic incremental validation on block insert
- **Validation cache**: Tracks last validated height for fast incremental validation
- **Height-based indexing**: Efficient block lookup by sequential height
- **Thread-shareable handle**: Clone a single open blockchain handle and use it across threads
- **Configurable database**: Multiple RocksDB presets for raw database access
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
use anyhow::Result;
use libblockchain::blockchain::open_chain;

fn main() -> Result<()> {
    // Create or open a blockchain
    let chain = open_chain("./my_blockchain")?;

    // Insert blocks (height auto-assigned, auto-validated, max 100MB)
    chain.put_block(b"Genesis data".to_vec(), b"sig0".to_vec())?;
    chain.put_block(b"Block 1 data".to_vec(), b"sig1".to_vec())?;
    chain.put_block(b"Block 2 data".to_vec(), b"sig2".to_vec())?;

    // Query blocks
    let (genesis, signature) = chain.get_block_by_height(0);
    let genesis = genesis?;
    let signature = signature?;
    println!("Genesis data: {:?}", genesis.block_data());
    println!("Genesis signature: {:?}", signature);

    // Get latest block
    let count = chain.block_count()?;
    if count > 0 {
        let (latest, _) = chain.get_block_by_height(count - 1);
        println!("Latest block data: {:?}", latest?.block_data());
    }

    // Validate entire blockchain integrity
    chain.validate()?;
    println!("Blockchain has {} blocks and is valid!", count);

    Ok(())
}
```

## Architecture

### Core Components

**Block Structures** ([src/block.rs](src/block.rs)):
- `BlockHeader`: Metadata (height, UUID, version, parent_hash, timestamp) - 100 bytes fixed
- `Block`: Complete block with header, SHA-512 hash, and data payload
- Height stored in header, assigned on insertion by counting existing blocks

**Blockchain Storage** ([src/blockchain.rs](src/blockchain.rs)):
- Single blockchain type: `BlockChain`
- Three RocksDB column families: `blocks`, `signatures`, and `validation_cache`
- Database is `DBWithThreadMode<MultiThreaded>` wrapped in `Arc` for shared ownership
- Helper function: `open_chain()`

**Database Configuration** ([src/db_model.rs](src/db_model.rs)):
- Presets: `high_performance()`, `high_durability()`, `read_only()`
- Builder pattern for customization
- Defaults: 512MB block cache, 64MB write buffer, LZ4 compression

### Database Structure

The blockchain uses two RocksDB column families:
- **`blocks`**: Maps block height (u64) → Block data
- **`signatures`**: Maps block height (u64) → signature bytes

### Shared Handle Model

The blockchain API exposes a single cloneable read/write handle:

```rust
use libblockchain::blockchain::{BlockChain, open_chain};
use std::thread;

let chain = open_chain("./my_blockchain")?;
let cloned = chain.clone();

thread::spawn(move || {
    cloned.put_block(b"hello".to_vec(), b"sig".to_vec())
})
.join()
.expect("worker thread panicked")?;

let _: BlockChain = chain;
```

## Usage Examples

### Opening a Blockchain

```rust
use libblockchain::blockchain::{BlockChain, open_chain};

// Method 1: Helper function
let chain = open_chain("./my_blockchain")?;

// Method 2: Direct constructor
let chain = BlockChain::open("./my_blockchain")?;
```

### Inserting Blocks

```rust
// Heights are assigned automatically (0, 1, 2, ...)
// Each block is auto-validated incrementally
// Maximum block size: 100MB
let height0 = chain.put_block(b"Genesis data".to_vec(), b"sig0".to_vec())?;
let height1 = chain.put_block(b"Block 1 data".to_vec(), b"sig1".to_vec())?;

println!("Inserted blocks at heights: {}, {}", height0, height1);

// Size limit enforcement
let large_data = vec![0u8; 101 * 1024 * 1024]; // 101MB
match chain.put_block(large_data, b"sig-large".to_vec()) {
    Err(e) => println!("Rejected: {}", e), // "Block data exceeds maximum size"
    Ok(_) => unreachable!(),
}
```

### Querying Blocks

```rust
// By height
let (block, signature) = chain.get_block_by_height(5);
let block = block?;
let signature = signature?;

// Access block fields
println!("Height: {}", block.height());
println!("Hash: {:?}", block.block_hash());
println!("Parent: {:?}", block.parent_hash());
println!("Data: {:?}", block.block_data());
println!("Signature: {:?}", signature);

// Get latest block
let count = chain.block_count()?;
if count > 0 {
    let (latest, latest_signature) = chain.get_block_by_height(count - 1);
    let latest = latest?;
    let latest_signature = latest_signature?;
    println!("Latest block: {} with signature {:?}", latest.height(), latest_signature);
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
chain.put_block(data, b"tx-signature".to_vec())?;

// Later, retrieve and deserialize
let count = chain.block_count()?;
let (block, _) = chain.get_block_by_height(count - 1);
let block = block?;
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

### `BlockChain`

**Opening:**
- `BlockChain::open(path) -> Result<Self>`: Open or create a blockchain

**Helper Functions:**
- `open_chain(path) -> Result<BlockChain>`

**Operations:**
- `block_count() -> Result<u64>`: Total blocks in chain
- `get_block_by_height(height: u64) -> (Result<Block>, Result<Vec<u8>>)`:
    Retrieve block and signature by height
- `get_signature_by_height(height: u64) -> Result<Vec<u8>>`: Retrieve signature
- `validate() -> Result<()>`: Verify chain integrity incrementally
- `validate_full() -> Result<()>`: Full validation from genesis to tip
- `validate_incremental() -> Result<u64>`: Validate blocks since the cached height
- `put_block(data: Vec<u8>, signature: Vec<u8>) -> Result<u64>`: Insert block and signature, returns height
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

The blockchain handle is thread-shareable.

- `BlockChain` stores `Arc<DBWithThreadMode<MultiThreaded>>`
- `BlockChain` implements `Clone`
- A cloned handle can be moved to another thread and used there

```rust
use std::thread;
use libblockchain::blockchain::open_chain;

let chain = open_chain("./my_blockchain")?;
let worker = chain.clone();

thread::spawn(move || worker.put_block(b"threaded".to_vec(), b"sig".to_vec()))
    .join()
    .expect("worker panicked")?;
```

## Performance Tips

**Read Performance:**
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
cargo test     # Run tests
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
