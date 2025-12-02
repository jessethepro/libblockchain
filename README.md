# libblockchain

A generic, lightweight Rust library for creating and managing blockchain blocks with persistent storage. This library provides core block structures, cryptographic primitives, and SledDB-backed persistence while remaining agnostic to the actual data you store in blocks.

## Features

- **Data-agnostic**: Store any application-specific data in blocks (JSON, binary, custom formats)
- **Persistent storage**: Built-in SledDB integration for blockchain persistence
- **Automatic height management**: Heights assigned automatically with thread-safe Mutex protection
- **Hybrid encryption**: RSA + AES-256-GCM encryption for block data
- **UUID-based indexing**: Efficient block lookup by UUID or height
- **Iterator support**: Traverse blocks in chain order
- **Configurable database**: Multiple SledDB presets (high performance, high durability, temporary, read-only)
- **Type-safe**: Strong typing with clear separation between cryptographic and metadata concerns

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
libblockchain = { git = "https://github.com/jessethepro/libblockchain.git" }
```

## Quick Start

```rust
use libblockchain::blockchain::BlockChain;
use openssl::x509::X509;

// Create or open a blockchain
let chain = BlockChain::new("./my_blockchain")?;

// Insert blocks (certificate needed for encryption)
chain.insert_block(b"Genesis data".to_vec(), cert.clone())?;
chain.insert_block(b"Block 1 data".to_vec(), cert.clone())?;
chain.insert_block(b"Block 2 data".to_vec(), cert)?;

// Query blocks
let genesis = chain.get_block_by_height(0)?.unwrap();
let latest = chain.get_latest_block()?.unwrap();
let count = chain.block_count()?;

// Iterate over all blocks
for block_result in chain.iter() {
    let block = block_result?;
    println!("Block hash: {:?}", block.block_hash);
}
```

## Architecture

### Core Components

- **`block`**: Block and BlockHeader structures with cryptographic hashing
  - `BlockHeader`: Contains cryptographically relevant data (version, parent_hash, timestamp, nonce, block_uid)
  - `Block`: Complete block with header, hash, encrypted data, and signature
- **`blockchain`**: Persistent blockchain storage with SledDB
  - Automatic height management with Mutex-protected counter
  - UUID-based block storage with separate height index
  - Iterator support for traversing blocks in order
- **`hybrid_encryption`**: RSA + AES-256-GCM encryption
  - RSA-OAEP for key encryption (supports 2048/4096-bit keys)
  - AES-256-GCM for data encryption with authentication
- **`db_model`**: SledDB configuration and presets
  - High performance, high durability, temporary, and read-only configurations
  - Builder pattern for custom settings

### Database Structure

The blockchain uses two SledDB trees:
- **`blocks`**: Maps block UUID (16 bytes) → serialized Block data
- **`height`**: Maps block height (u64 as big-endian bytes) → block UUID

### Design Decisions

- **Block height is automatic**: Managed internally by the blockchain, not passed by users
- **UUID-based storage**: Blocks stored by UUID for efficient direct lookup
- **Height index**: Separate index for sequential access and iteration
- **Mutex-protected height**: Thread-safe concurrent block insertion
- **Opaque data**: `block_data: Vec<u8>` allows any application-specific payload
- **Hybrid encryption**: All block data is encrypted using X509 certificates

## Usage Examples

### Creating a Blockchain

```rust
use libblockchain::blockchain::BlockChain;

// Create a new blockchain (or open existing)
let chain = BlockChain::new("./blockchain_data")?;

// Check if empty
if chain.block_count()? == 0 {
    println!("New blockchain created");
}
```

### Inserting Blocks

```rust
use openssl::x509::X509;

// Load your certificate for encryption
let cert = load_certificate()?;

// Insert genesis block (automatic)
chain.insert_block(b"Genesis data".to_vec(), cert.clone())?;

// Insert subsequent blocks (heights assigned automatically)
chain.insert_block(b"Transaction 1".to_vec(), cert.clone())?;
chain.insert_block(b"Transaction 2".to_vec(), cert)?;
```

### Querying Blocks

```rust
// By height
let genesis = chain.get_block_by_height(0)?;
let block5 = chain.get_block_by_height(5)?;

// By UUID
let uuid = genesis.unwrap().block_header.block_uid;
let same_block = chain.get_block_by_uuid(&uuid)?;

// Latest block
let latest = chain.get_latest_block()?;

// Check existence
let exists = chain.block_exists(&uuid)?;
```

### Iterating Over Blocks

```rust
// Process all blocks in order
for block_result in chain.iter() {
    let block = block_result?;
    println!("Block at timestamp {}: {:?}", 
             block.block_header.timestamp, 
             block.block_hash);
}

// Collect into vector
let blocks: Vec<_> = chain.iter()
    .collect::<anyhow::Result<Vec<_>>>()?;
```

### Custom Database Configuration

```rust
use libblockchain::db_model::{SledDb, FlushMode};

// Use a preset
let chain = {
    let db = SledDb::high_performance("./fast_blockchain").open()?;
    // ... create BlockChain from db
};

// Or customize
let db = SledDb::new("./custom_blockchain")
    .with_cache_capacity_mb(2048)  // 2GB cache
    .with_flush_mode(FlushMode::Auto)
    .with_flush_every_ms(5000)     // Flush every 5 seconds
    .open()?;
```

### Storing Custom Data

```rust
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct Transaction {
    from: String,
    to: String,
    amount: u64,
    timestamp: u64,
}

let transaction = Transaction {
    from: "Alice".to_string(),
    to: "Bob".to_string(),
    amount: 100,
    timestamp: 1701475200,
};

// Serialize and insert
let data = serde_json::to_vec(&transaction)?;
chain.insert_block(data, cert)?;

// Later, retrieve and deserialize
let block = chain.get_latest_block()?.unwrap();
let tx: Transaction = serde_json::from_slice(&block.block_data)?;
```

## API Reference

### `BlockChain`

**Creation:**
- `new<P: AsRef<Path>>(path: P) -> Result<Self>`: Open or create blockchain

**Insertion:**
- `insert_block(&self, block_data: Vec<u8>, app_cert: X509) -> Result<()>`: Insert new block

**Queries:**
- `get_block_by_height(&self, height: u64) -> Result<Option<Block>>`: Get block by height
- `get_block_by_uuid(&self, uuid: &[u8; 16]) -> Result<Option<Block>>`: Get block by UUID
- `get_latest_block(&self) -> Result<Option<Block>>`: Get most recent block
- `block_exists(&self, uuid: &[u8; 16]) -> Result<bool>`: Check if block exists
- `block_count(&self) -> Result<usize>`: Get total block count
- `get_height(&self) -> Result<u64>`: Get height of last block

**Iteration:**
- `iter(&self) -> BlockIterator<'_>`: Create iterator over all blocks

### `Block`

```rust
pub struct Block {
    pub block_header: BlockHeader,
    pub block_hash: [u8; 32],
    pub block_data: Vec<u8>,          // Encrypted with hybrid encryption
    pub block_signature: Vec<u8>,
}
```

**Methods:**
- `new_genesis_block(data: Vec<u8>, cert: X509) -> Self`: Create genesis block
- `new_regular_block(parent_hash: [u8; 32], data: Vec<u8>, cert: X509) -> Self`: Create regular block
- `serialize_block(&self) -> Vec<u8>`: Serialize block for storage

### `BlockHeader`

```rust
pub struct BlockHeader {
    pub block_uid: uuid::Bytes,      // 16-byte UUID
    pub version: u32,                 // Header version (currently 1)
    pub parent_hash: [u8; 32],       // Hash of parent block
    pub timestamp: u64,               // Unix timestamp
    pub nonce: u64,                   // Random nonce
}
```

### Database Configuration

**Presets:**
- `SledDb::high_performance(path)`: Large cache, async flush
- `SledDb::high_durability(path)`: Compression, sync flush
- `SledDb::temporary()`: In-memory, deleted on close
- `SledDb::read_only(path)`: Read-only access

**Builder methods:**
- `with_cache_capacity(bytes)`: Set cache size
- `with_flush_mode(mode)`: Set flush mode (Auto/EveryOp/Never)
- `with_flush_every_ms(ms)`: Set flush interval
- `with_compression(factor)`: Enable compression

## Testing

Run the test suite:

```bash
cargo test
```

The library includes:
- 24 unit tests for core functionality
- 6 integration tests demonstrating real-world usage
- 5 documentation tests

All tests passing ✓

## Thread Safety

`BlockChain` is safe to share across threads:
- The `current_height` field is protected by a `Mutex`
- SledDB is internally lock-free and thread-safe
- Multiple threads can safely insert blocks concurrently

## Performance Considerations

- **Cache size**: Larger cache improves read performance (default: 512MB)
- **Flush mode**: Auto mode balances performance and durability
- **Compression**: Reduces disk usage but adds CPU overhead (disabled by default)
- **Iterator**: Queries database per block, consider collecting into Vec for multiple passes

## Security

- All block data is encrypted using hybrid RSA + AES-256-GCM encryption
- AES-GCM provides authenticated encryption (detects tampering)
- RSA-OAEP for secure key encapsulation
- Random nonces ensure unique encryption per block
- X509 certificates required for encryption operations

## Contributing

Contributions should maintain:
- Data format agnosticism
- Thread safety
- Comprehensive test coverage
- Clear documentation

## License

[Specify your license here]

## What This Library Does **Not** Include

This is a foundational library designed to be extended by consumer applications. It does **not** include:
- Consensus mechanisms (PoW, PoS, PBFT, etc.)
- Networking/peer-to-peer communication
- Transaction validation logic
- Smart contract execution
- Merkle trees or other advanced data structures
- Mining or block production algorithms

These are intentionally left to consumer applications to implement based on their specific requirements.

## Dependencies

- `sled`: Embedded database (0.34)
- `openssl`: Cryptographic operations (0.10)
- `anyhow`: Error handling (1.0)
- `serde`: Serialization (1.0)
- `uuid`: Block identifiers (1.11)
- `rand`: Random generation (0.8)
- `libcertcrypto`: Certificate tools (path dependency)
