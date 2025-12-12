# libblockchain

A generic, lightweight Rust library for creating and managing blockchain blocks with persistent storage. This library provides core block structures, cryptographic primitives, and RocksDB-backed persistence while remaining agnostic to the actual data you store in blocks. To create or open a blockchain, the library requires the path to a Openssl RSA Private Key in PEM format. On Linux, I use the openssl command to generate a 4096 bit application key. The library will prompt the user for the password on the command line. The RSA Private Key file contains both the Private and Public keys and is used to encrypt/decrypt AES Keys. Unique AES GCM 256 bit keys are generated for each block transaction. Once the RSA Private Key file is loaded at application start, it can be removed from the file system and returned to its secure offline storage.

## Features

- **Data-agnostic**: Store any application-specific data in blocks (JSON, binary, custom formats)
- **Persistent storage**: Built-in RocksDB integration for blockchain persistence
- **Automatic height management**: Heights assigned automatically with thread-safe Mutex protection
- **Hybrid encryption**: RSA + AES-256-GCM encryption for block data
- **Secure key storage**: Private keys protected with `secrecy` crate, auto-extracts public keys
- **UUID-based indexing**: Efficient block lookup by UUID or height
- **Iterator support**: Traverse blocks in chain order
- **Configurable database**: Multiple RocksDB presets (high performance, high durability, read-only)
- **Type-safe**: Strong typing with clear separation between cryptographic and metadata concerns
- **SHA-512 hashing**: 64-byte cryptographic hashes for block integrity

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
libblockchain = { git = "https://github.com/jessethepro/libblockchain.git" }
```

## Quick Start

```rust
use libblockchain::blockchain::BlockChain;

// Create or open a blockchain with your private key
// You'll be prompted for the password interactively
// The public key is automatically extracted and stored
let chain = BlockChain::new("./my_blockchain", "./private_key.pem")?;

// Insert blocks (automatically encrypted with AES-256-GCM + RSA-OAEP)
chain.put_block(b"Genesis data".to_vec())?;
chain.put_block(b"Block 1 data".to_vec())?;
chain.put_block(b"Block 2 data".to_vec())?;

// Query blocks (automatically decrypted)
let genesis = chain.get_block_by_height(0)?;
let latest = chain.get_latest_block()?;
let count = chain.block_count()?;

// Access decrypted block data
println!("Genesis data: {:?}", String::from_utf8_lossy(&genesis.block_data));

// Iterate over all blocks
for block_result in chain.iter() {
    let block = block_result?;
    println!("Block hash: {:?}", block.block_hash);
}

// Validate entire blockchain integrity
chain.validate()?;
```

## Architecture
- **`blockchain`**: Persistent blockchain storage with RocksDB
  - Automatic height management with Mutex-protected counter
  - UUID-based block storage with separate height index
  - Iterator support for traversing blocks in order
  - Integrated hybrid RSA-OAEP + AES-256-GCM encryption
  - Private keys protected using `secrecy` crate with automatic zeroing
  - Automatic public key extraction from private keys
  - Interactive password prompting for encrypted private keys
  - Thread-safe with Arc-wrapped database
- **`block`**: Core block structures
  - Block and BlockHeader with SHA-512 hashing
  - UUID-based block identification
  - Serialization/deserialization support
- **`db_model`**: RocksDB configuration and presets
  - High performance, high durability, and read-only configurations
  - Builder pattern for custom settings
  - Column families for organizing data

### Database Structure

The blockchain uses two RocksDB column families:
- **`blocks`**: Maps block UUID (16 bytes) → serialized Block data
- **`height`**: Maps block height (u64 as big-endian bytes) → block UUID

- **Opaque data**: `block_data: Vec<u8>` allows any application-specific payload
- **Hybrid encryption**: AES-256-GCM for data, RSA-OAEP for key encryption
- **Secure key management**: Private keys protected with `secrecy` crate, zeroed on drop
- **Interactive security**: Password prompting for encrypted private keys
- **Block height is automatic**: Managed internally by the blockchain, not passed by users
- **UUID-based storage**: Blocks stored by UUID for efficient direct lookup
- **Height index**: Separate index for sequential access and iteration
- **Mutex-protected height**: Thread-safe concurrent block insertion

## Usage Examples
### Creating a Blockchain

```rust
use libblockchain::blockchain::BlockChain;
use openssl::rsa::Rsa;
use openssl::pkey::PKey;

// Generate a new RSA key pair (2048 or 4096 bits recommended)
let rsa = Rsa::generate(2048)?;
let private_key = PKey::from_rsa(rsa)?;

// Save the private key to a PEM file (optionally with password)
let pem = private_key.private_key_to_pem_pkcs8_passphrase(
    openssl::symm::Cipher::aes_256_cbc(),
    b"your-secure-password"
)?;
std::fs::write("./private_key.pem", pem)?;

// Create blockchain (will prompt for password if key is encrypted)
let chain = BlockChain::new("./my_blockchain", "./private_key.pem")?;

### Inserting Blocks

```rust
// Insert genesis block (automatic height assignment)
// Data is automatically encrypted with AES-256-GCM + RSA-OAEP
chain.put_block(b"Genesis data".to_vec())?;

// Insert subsequent blocks (heights assigned automatically)
chain.put_block(b"Transaction 1".to_vec())?;
chain.put_block(b"Transaction 2".to_vec())?;

println!("Total blocks: {}", chain.block_count()?);
```

### Querying Blocks

```rust
// By height (automatically decrypted)
let genesis = chain.get_block_by_height(0)?;
let block5 = chain.get_block_by_height(5)?;

// Access decrypted data directly
println!("Genesis data: {:?}", String::from_utf8_lossy(&genesis.block_data));

// By UUID
let uuid = genesis.block_header.block_uid;
let same_block = chain.get_block_by_uuid(&uuid)?;

// Latest block
let latest = chain.get_latest_block()?;

// Check existence
let exists = chain.block_exists(&uuid)?;
### Iterating Over Blocks

```rust
// Process all blocks in order (automatically decrypted)
for block_result in chain.iter() {
    let block = block_result?;
    println!("Block at timestamp {}: hash {:?}", 
             block.block_header.timestamp,
             block.block_hash);
}

// Collect into vector
let blocks: Vec<_> = chain.iter()
    .collect::<anyhow::Result<Vec<_>>>()?;

// Validate entire blockchain
chain.validate()?;
println!("Blockchain is valid!");
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

// Serialize and insert (automatically encrypted)
let data = serde_json::to_vec(&transaction)?;
chain.put_block(data)?;

// Later, retrieve and deserialize (automatically decrypted)
let block = chain.get_block_by_height(chain.get_height()?)?;
let tx: Transaction = serde_json::from_slice(&block.block_data)?;
println!("Transaction: {} -> {}, amount: {}", tx.from, tx.to, tx.amount);

### `BlockChain`

**Creation:**
- `new<P: AsRef<Path>>(path: P, private_key_path: P) -> Result<Self>`: Open or create blockchain with private key (prompts for password)

**Insertion:**
- `put_block(&self, block_data: Vec<u8>) -> Result<()>`: Insert new block (automatically encrypted with AES-256-GCM + RSA-OAEP)

**Querying:**
- `get_block_by_height(&self, height: u64) -> Result<Block>`: Get block by height (automatically decrypted)
- `get_block_by_uuid(&self, uuid: &[u8; 16]) -> Result<Option<Block>>`: Get block by UUID
- `get_latest_block(&self) -> Result<Block>`: Get most recent block
- `block_exists(&self, uuid: &[u8; 16]) -> Result<bool>`: Check if block exists
- `block_count(&self) -> Result<usize>`: Get total block count
- `get_height(&self) -> Result<u64>`: Get height of last block

**Validation:**
- `validate(&self) -> Result<()>`: Validate entire blockchain integrity

**Iteration:**
- `iter(&self) -> BlockIterator<'_>`: Create iterator over all blocks (automatically decrypts)
```rust
pub struct Block {
    pub block_header: BlockHeader,
    pub block_hash: [u8; 64],        // SHA-512 hash (64 bytes)
    pub block_data: Vec<u8>,         // Application data (decrypted when retrieved)
    pub block_signature: Vec<u8>,
}
```

**Methods:**
- `new_genesis_block(data: Vec<u8>) -> Self`: Create genesis block
- `new_regular_block(parent_hash: [u8; 64], data: Vec<u8>) -> Self`: Create regular block  
- `bytes(&self) -> Vec<u8>`: Serialize block to bytes
- `from_bytes(bytes: &[u8]) -> Result<Self>`: Deserialize block from bytes
```
```rust
pub struct BlockHeader {
    pub block_uid: uuid::Bytes,      // 16-byte UUID
    pub version: u32,                 // Header version (currently 1)
    pub parent_hash: [u8; 64],       // SHA-512 hash of parent block
    pub timestamp: u64,               // Unix timestamp
    pub nonce: u64,                   // Random nonce
}
```

**Methods:**
- `generate_block_hash(&self) -> [u8; 64]`: Generate SHA-512 hash of header

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

The library includes:
- 29 unit tests for core functionality
- 6 integration tests demonstrating real-world usage
- 8 documentation tests

All tests passing ✓
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
## Security

- All block data is encrypted using hybrid RSA + AES-256-GCM encryption
- AES-GCM provides authenticated encryption (detects tampering)
- RSA-OAEP for secure key encapsulation
- Random nonces ensure unique encryption per block
- Private keys protected using `secrecy` crate with automatic zeroing
- SHA-512 hashing for block integrity verification
- Blockchain validation ensures parent-child hash integrityollecting into Vec for multiple passes

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

MIT License - see [LICENSE](LICENSE) file for details.

Copyright (c) 2025 jessethepro

## What This Library Does **Not** Include

This is a foundational library designed to be extended by consumer applications. It does **not** include:
- Consensus mechanisms (PoW, PoS, PBFT, etc.)
- Networking/peer-to-peer communication
- Transaction validation logic
- Smart contract execution
- Merkle trees or other advanced data structures
- `sled`: Embedded database (0.34)
- `openssl`: Cryptographic operations (0.10)
- `anyhow`: Error handling (1.0)
- `serde`: Serialization (1.0)
- `uuid`: Block identifiers (1.11)
- `rand`: Random generation (0.8)
- `secrecy`: Secure secret handling (0.10.3)
- `rpassword`: Interactive password prompting (8.0)
