# libblockchain

A generic, lightweight Rust library for creating and managing blockchain blocks. This library provides core block structures and cryptographic primitives while remaining agnostic to the actual data you store in blocks.

## Features

- **Data-agnostic**: Store any application-specific data in blocks (JSON, binary, custom formats)
- **Pluggable hashing**: Implement your own hashing algorithm via the `BlockHeaderHasher` trait
- **Genesis & regular blocks**: Explicit traits for creating genesis vs. regular blocks
- **Type-safe**: Strong typing with clear separation between cryptographic and metadata concerns
- **Zero dependencies for core types**: Minimal dependency footprint (only uuid and rand for block creation)

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
libblockchain = { git = "https://github.com/jessethepro/libblockchain.git" }
```

## Quick Start

```rust
use libblockchain::{Block, BlockHeaderHasher, GenesisBlock, RegularBlock};

// 1. Implement a hasher for your chosen algorithm
struct MyHasher;

impl BlockHeaderHasher for MyHasher {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        // Use your preferred hashing algorithm (SHA-256, BLAKE3, etc.)
        // This example uses a placeholder
        vec![0u8; 32]
    }

    fn hash_size(&self) -> usize {
        32
    }
}

// 2. Create a genesis block
let hasher = MyHasher;
let genesis = Block::new_genesis(&hasher, b"Genesis data".to_vec());

// 3. Create subsequent blocks
let block2 = Block::new_block(
    &hasher,
    genesis.block_hash,
    b"Block 2 data".to_vec()
);

let block3 = Block::new_block(
    &hasher,
    block2.block_hash,
    b"Block 3 data".to_vec()
);
```

## Architecture

### Core Components

- **`BlockHeader`**: Contains cryptographically relevant data (version, parent_hash, timestamp, nonce, block_uid)
- **`Block`**: Complete block with header, hash, and application-specific data
- **`BlockHeaderHasher` trait**: Allows custom hashing algorithm implementations
- **`GenesisBlock` trait**: For creating the first block in a chain (parent_hash = all zeros)
- **`RegularBlock` trait**: For creating subsequent blocks linked to a parent

### Design Decisions

- **Block height is external**: Stored as database metadata, not in the block header
- **Hash duplication**: `block_hash` is stored for convenience (also derivable from header)
- **Opaque data**: `block_data: Vec<u8>` allows any application-specific payload
- **Trait-based construction**: Explicit distinction between genesis and regular blocks

## Usage Examples

### Using SHA-256 Hashing

```rust
use sha2::{Sha256, Digest};
use libblockchain::{Block, BlockHeaderHasher, GenesisBlock, RegularBlock};

struct Sha256Hasher;

impl BlockHeaderHasher for Sha256Hasher {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    fn hash_size(&self) -> usize {
        32
    }
}

let hasher = Sha256Hasher;
let genesis = Block::new_genesis(&hasher, b"My blockchain".to_vec());
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

let transaction = Transaction {
    from: "Alice".to_string(),
    to: "Bob".to_string(),
    amount: 100,
};

let data = serde_json::to_vec(&transaction).unwrap();
let block = Block::new_genesis(&hasher, data);
```

### Building a Chain

```rust
let mut chain = Vec::new();

// Genesis block
chain.push(Block::new_genesis(&hasher, b"Genesis".to_vec()));

// Add more blocks
for i in 1..=10 {
    let prev_hash = chain.last().unwrap().block_hash;
    let data = format!("Block {}", i).into_bytes();
    chain.push(Block::new_block(&hasher, prev_hash, data));
}

// Verify chain integrity
for i in 1..chain.len() {
    assert_eq!(
        chain[i].block_header.parent_hash,
        chain[i - 1].block_hash
    );
}
```

## API Reference

### `BlockHeader`

```rust
pub struct BlockHeader {
    pub block_uid: uuid::Bytes,      // Unique identifier
    pub version: u32,                 // Header version
    pub parent_hash: [u8; 32],       // Hash of parent block
    pub timestamp: u64,               // Unix timestamp
    pub nonce: u64,                   // Random nonce for entropy
}
```

### `Block`

```rust
pub struct Block {
    pub block_header: BlockHeader,
    pub block_hash: [u8; 32],
    pub block_data: Vec<u8>,
}
```

**Methods:**
- `header_bytes() -> Vec<u8>`: Serialize header for hashing
- `header_hash<H>(&self, hasher: &H) -> Vec<u8>`: Compute header hash

### Traits

**`BlockHeaderHasher`**
- `hash(&self, data: &[u8]) -> Vec<u8>`: Hash data
- `hash_size(&self) -> usize`: Return hash size in bytes

**`GenesisBlock`**
- `new_genesis<H>(hasher: &H, block_data: Vec<u8>) -> Self`: Create genesis block

**`RegularBlock`**
- `new_block<H>(hasher: &H, parent_hash: [u8; 32], block_data: Vec<u8>) -> Self`: Create regular block

## Testing

Run the test suite:

```bash
cargo test
```

The library includes:
- 7 unit tests for core functionality
- 6 integration tests demonstrating real-world usage

## Contributing

This is a foundational library designed to be extended by consumer applications. Contributions should maintain:
- Data format agnosticism
- Minimal dependencies
- Clear separation between cryptographic and application concerns

## License

[Specify your license here]

## Related Projects

This library is designed to be a building block for blockchain applications. It does **not** include:
- Consensus mechanisms (PoW, PoS, etc.)
- Networking/peer-to-peer communication
- Transaction validation logic
- Smart contract execution

These are intentionally left to consumer applications to implement based on their specific requirements.
