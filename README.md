# libblockchain

A generic, lightweight Rust library for creating and managing blockchain blocks with persistent storage. This library provides core block structures, cryptographic primitives, and RocksDB-backed persistence while remaining agnostic to the actual data you store in blocks. Private keys are stored securely in the Linux kernel keyring, isolated from userspace and never written to disk. The RSA private key is used to encrypt/decrypt unique AES-GCM-256 keys generated for each block.

## Features

- **Data-agnostic**: Store any application-specific data in blocks (JSON, binary, custom formats)
- **Persistent storage**: Built-in RocksDB integration for blockchain persistence
- **Automatic height management**: Heights assigned automatically for sequential block ordering
- **Hybrid encryption**: RSA-OAEP + AES-256-GCM encryption for block data
- **Kernel keyring storage**: Private keys stored in Linux kernel keyring, isolated and secure, with configurable key names
- **Height-based indexing**: Efficient block lookup by height
- **Native RocksDB iterator**: Efficient traversal using RocksDB's built-in iteration
- **Configurable database**: Multiple RocksDB presets (high performance, high durability, read-only)
- **Type-safe**: Strong typing with clear separation between cryptographic and metadata concerns
- **SHA-512 hashing**: 64-byte cryptographic hashes for block integrity

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
libblockchain = { git = "https://github.com/jessethepro/libblockchain.git" }
```

### Build Requirements

**Important**: This library compiles RocksDB and OpenSSL from source:
- **RocksDB**: Compiled with `mt_static` feature (multi-threaded static linking)
- **OpenSSL**: Compiled with `vendored` feature (builds from source)

The first build may take **5-10 minutes** due to C++ compilation. You'll need:
- C++ compiler (g++ or clang)
- CMake (for RocksDB)
- Standard build tools (make, etc.)
- Linux kernel 3.10+ (for keyring support)

Subsequent builds are faster as dependencies are cached.

## Quick Start

```rust
use libblockchain::blockchain::BlockChain;
use keyutils::{Keyring, SpecialKeyring};

// Attach to the process keyring (keys must be pre-loaded using keyctl)
// Example: keyctl padd user my-app-key @p < private_key.der
let keyring = Keyring::attach(SpecialKeyring::Process)?;

// Create or open a blockchain using the keyring with a custom key name
let chain = BlockChain::new("./my_blockchain", keyring, "my-app-key".to_string())?;

// Insert blocks (automatically encrypted with AES-256-GCM + RSA-OAEP)
chain.put_block(b"Genesis data".to_vec())?;
chain.put_block(b"Block 1 data".to_vec())?;

// Query blocks (automatically decrypted)
let genesis = chain.get_block_by_height(0)?;
let max_height = chain.get_max_height()?;
let latest = chain.get_block_by_height(max_height)?;

// Iterate over all blocks
for block_result in chain.iter() {
    let block = block_result?;
    println!("Block {}: {:?}", block.block_header.height, block.block_hash);
}

// Validate entire blockchain integrity
chain.validate()?;
```

## Architecture

### Components

- **`blockchain`**: Persistent blockchain storage with RocksDB
  - Height-based block storage (blocks keyed by u64 height)
  - Native RocksDB iterator for efficient sequential access
  - Integrated hybrid RSA-OAEP + AES-256-GCM encryption
  - Private keys stored in Linux kernel keyring via `keyutils`
  - Automatic public key extraction from private keys
  - Thread-safe database operations

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
- **`blocks`**: Maps block height (u64) → encrypted Block data
- **`signatures`**: Maps block height (u64) → signature data

### Key Design Decisions

- **Opaque data**: `block_data: Vec<u8>` allows any application-specific payload
- **Selective encryption**: Only `block_data` is encrypted; BlockHeader and hash stored in plaintext
- **Hybrid encryption**: AES-256-GCM for data, RSA-OAEP (SHA-256 MGF1) for AES key encapsulation
- **Kernel keyring storage**: Private keys stored in Linux kernel keyring, isolated from userspace
- **No disk persistence**: Keys remain in kernel memory, never written to disk
- **Height-based storage**: Blocks keyed directly by height for efficient sequential access
- **Automatic height assignment**: Heights managed internally, assigned sequentially

## Usage Examples

### Setting Up Keys

```rust
use keyutils::{Keyring, SpecialKeyring};
use openssl::rsa::Rsa;
use openssl::pkey::PKey;

// Generate a new RSA key pair (4096 bits recommended)
let rsa = Rsa::generate(4096)?;
let private_key = PKey::from_rsa(rsa)?;

// Export as DER for keyring storage
let der = private_key.private_key_to_der()?;

// Add key to the Linux kernel keyring with a custom name
let mut keyring = Keyring::attach_or_create(SpecialKeyring::Process)?;
keyring.add_key::<keyutils::keytypes::user::User, _, _>("my-app-key", &der)?;

// Or from command line:
// openssl genrsa 4096 | openssl rsa -outform DER | keyctl padd user my-app-key @p
```

### Creating and Using a Blockchain

```rust
use libblockchain::blockchain::BlockChain;
use keyutils::{Keyring, SpecialKeyring};

// Attach to the keyring
let keyring = Keyring::attach(SpecialKeyring::Process)?;

// Create blockchain with the key name you used when adding the key
let chain = BlockChain::new("./my_blockchain", keyring, "my-app-key".to_string())?;

// Insert blocks (automatic height assignment and encryption)
chain.put_block(b"Genesis data".to_vec())?;
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

// Get latest block
let max_height = chain.get_max_height()?;
if max_height > 0 {
    let latest = chain.get_block_by_height(max_height)?;
    println!("Latest block data: {:?}", String::from_utf8_lossy(&latest.block_data));
}
```

### Iterating Over Blocks

```rust
// Process all blocks in order (automatically decrypted)
for block_result in chain.iter() {
    let block = block_result?;
    println!("Block {} at timestamp {}: hash {:?}", 
             block.block_header.height,
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
let max_height = chain.get_max_height()?;
let block = chain.get_block_by_height(max_height)?;
let tx: Transaction = serde_json::from_slice(&block.block_data)?;
println!("Transaction: {} -> {}, amount: {}", tx.from, tx.to, tx.amount);
```

### Custom Database Configuration

```rust
use libblockchain::db_model::RocksDbModel;

// Use a preset configuration
let db = RocksDbModel::high_performance("./fast_blockchain")
    .with_column_family("blocks")
    .with_column_family("signatures")
    .open()?;

// Or fully customize
let db = RocksDbModel::new("./custom_blockchain")
    .with_block_cache_size_mb(2048)  // 2GB cache
    .with_write_buffer_size_mb(256)  // 256MB write buffer
    .with_compression(libblockchain::db_model::CompressionType::Zstd)
    .with_sync_writes(true)
    .with_column_family("blocks")
    .with_column_family("signatures")
    .open()?;
```

## API Reference

### `BlockChain`

**Creation:**
- `new<P: AsRef<Path>>(path: P, proc_keyring: Keyring, app_key_name: String) -> Result<Self>`: Open or create blockchain using Linux kernel keyring for key storage with a custom key name

**Insertion:**
- `put_block(&self, block_data: Vec<u8>) -> Result<()>`: Insert new block (automatically encrypted with AES-256-GCM + RSA-OAEP)
- `put_signature(&self, height: u64, signature: Vec<u8>) -> Result<()>`: Store signature for a block

**Querying:**
- `get_block_by_height(&self, height: u64) -> Result<Block>`: Get block by height (automatically decrypted)
- `get_signature_by_height(&self, height: u64) -> Result<Vec<u8>>`: Get signature for a block
- `get_max_height(&self) -> Result<u64>`: Get height of last block
- `block_count(&self) -> Result<u64>`: Get total block count
- `delete_latest_block(&self) -> Result<Option<u64>>`: Delete the most recently inserted block

**Validation:**
- `validate(&self) -> Result<()>`: Validate entire blockchain integrity

**Iteration:**
- `iter(&self) -> BlockIterator<'_>`: Create RocksDB-backed iterator over all blocks (automatically decrypts)

### `Block`

```rust
pub struct Block {
    pub block_header: BlockHeader,
    pub block_hash: [u8; 64],        // SHA-512 hash (64 bytes)
    pub block_data: Vec<u8>,         // Application data (decrypted when retrieved)
}
```

**Methods:**
- `new_genesis_block(data: Vec<u8>) -> Self`: Create genesis block (height 0)
- `new_regular_block(height: u64, parent_hash: [u8; 64], data: Vec<u8>) -> Self`: Create regular block
- `bytes(&self) -> Vec<u8>`: Serialize block to bytes
- `from_bytes(bytes: &[u8]) -> Result<Self>`: Deserialize block from bytes

### `BlockHeader`

```rust
pub struct BlockHeader {
    pub height: u64,                  // Block height in chain
    pub block_uid: [u8; 16],         // 16-byte UUID
    pub version: u32,                 // Header version (currently 1)
    pub parent_hash: [u8; 64],       // SHA-512 hash of parent block
    pub timestamp: u64,               // Unix timestamp (seconds since epoch)
}
```

**Methods:**
- `generate_block_hash(&self) -> [u8; 64]`: Generate SHA-512 hash of header

### `RocksDbModel`

**Presets:**
- `RocksDbModel::new(path)`: Default configuration
- `RocksDbModel::high_performance(path)`: Large cache, optimized for speed
- `RocksDbModel::high_durability(path)`: Sync writes, optimized for safety
- `RocksDbModel::read_only(path)`: Read-only access

**Builder methods:**
- `with_block_cache_size_mb(mb)`: Set cache size in megabytes
- `with_write_buffer_size_mb(mb)`: Set write buffer size in megabytes
- `with_compression(type)`: Set compression algorithm
- `with_sync_writes(bool)`: Enable/disable sync writes
- `with_column_family(name)`: Add a column family
- `open() -> Result<DB>`: Open the database

## Thread Safety

`BlockChain` is safe to share across threads:
- RocksDB provides thread-safe concurrent reads
- Write operations are serialized by RocksDB's internal locking
- Multiple threads can safely query blocks concurrently
- Insert operations are automatically serialized

## Security

- **Hybrid Encryption**: RSA-OAEP + AES-256-GCM for each block
- **Authenticated Encryption**: AES-GCM detects tampering
- **Key Encapsulation**: RSA-OAEP (SHA-256 MGF1) for secure AES key distribution
- **Random Nonces**: Unique 96-bit nonce per block ensures semantic security
- **Kernel Keyring**: Private keys isolated in kernel memory, never on disk
- **Process Isolation**: Keys accessible only within the process keyring scope
- **SHA-512 Hashing**: Cryptographic block integrity verification
- **Chain Validation**: Parent-child hash relationships enforced

## Dependencies

Core dependencies:
- `rocksdb`: Embedded database (0.24)
- `openssl`: Cryptographic operations (0.10)
- `keyutils`: Linux kernel keyring access (0.4)
- `anyhow`: Error handling (1.0)
- `serde`: Serialization (1.0)
- `uuid`: Block identifiers (1.18)
- `rand`: Random generation (0.9)

## What This Library Does NOT Include

This is a foundational library designed to be extended by applications. It does **not** include:

- Consensus mechanisms (PoW, PoS, PBFT, etc.)
- Networking/peer-to-peer communication
- Transaction validation logic
- Smart contract execution
- Merkle trees
- Mining algorithms
- Wallet management
- Cryptocurrency features

## Contributing

Contributions are welcome! Please ensure:
- Data format agnosticism is maintained
- Thread safety is preserved
- Comprehensive test coverage
- Clear documentation
- Code passes `cargo clippy` and `cargo test`

## License

MIT License - see [LICENSE](LICENSE) file for details.

Copyright (c) 2025 jessethepro

## Acknowledgments

Built with:
- [RocksDB](https://rocksdb.org/) - High-performance embedded database
- [OpenSSL](https://www.openssl.org/) - Cryptographic library
- [keyutils](https://people.redhat.com/~dhowells/keyutils/) - Linux kernel keyring interface
