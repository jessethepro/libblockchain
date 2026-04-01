# AI Agent Integration Guide for libblockchain

**Target Audience**: AI coding agents integrating libblockchain into external projects  
**Library Version**: 0.1.0  
**Last Updated**: April 2026

## Current API Shape

The blockchain layer uses one shared read/write handle.

- Open with `open_chain(path)` or `BlockChain::open(path)`
- Clone the returned handle to use it across threads
- `put_block()` takes both block data and signature bytes
- `get_block_by_height()` returns a pair: `(Result<Block>, Result<Vec<u8>>)`

There is no separate blockchain read-only open path in the current API.

## Minimal Example

```rust
use anyhow::Result;
use libblockchain::blockchain::open_chain;

fn main() -> Result<()> {
    let chain = open_chain("./my_blockchain")?;

    let height0 = chain.put_block(b"Genesis data".to_vec(), b"sig0".to_vec())?;
    let height1 = chain.put_block(b"Block 1 data".to_vec(), b"sig1".to_vec())?;

    let (block, signature) = chain.get_block_by_height(height1);
    let block = block?;
    let signature = signature?;

    println!("Block {}", block.height());
    println!("Payload: {:?}", block.block_data());
    println!("Signature: {:?}", signature);

    chain.validate()?;
    println!("Chain contains {} blocks", chain.block_count()?);

    let _ = height0;
    Ok(())
}
```

## Core API

### Opening

```rust
use libblockchain::blockchain::{BlockChain, open_chain};

let chain = open_chain("./my_blockchain")?;
let chain = BlockChain::open("./my_blockchain")?;
```

### Writing Blocks

```rust
let height = chain.put_block(b"payload".to_vec(), b"signature".to_vec())?;
chain.put_signature(height, b"replacement-signature".to_vec())?;
```

### Reading Blocks

```rust
let (block, signature) = chain.get_block_by_height(0);
let block = block?;
let signature = signature?;

println!("height = {}", block.height());
println!("hash = {:?}", block.block_hash());
println!("signature = {:?}", signature);
```

### Validation

```rust
chain.validate()?;
chain.validate_full()?;
let upto = chain.validate_incremental()?;
println!("validated through height {}", upto);
```

### Deletion

```rust
if let Some(height) = chain.delete_last_block()? {
    println!("Deleted block {}", height);
}
```

## Thread Sharing

The blockchain handle is cloneable and safe to share across threads.

```rust
use anyhow::{Result, anyhow};
use libblockchain::blockchain::open_chain;
use std::thread;

fn threaded_write() -> Result<()> {
    let chain = open_chain("./my_blockchain")?;
    let writer = chain.clone();

    let height = thread::spawn(move || {
        writer.put_block(b"thread payload".to_vec(), b"thread sig".to_vec())
    })
    .join()
    .map_err(|_| anyhow!("worker thread panicked"))??;

    println!("Inserted block {} from another thread", height);
    Ok(())
}
```

Internally, `BlockChain` stores `Arc<DBWithThreadMode<MultiThreaded>>`.

## Common Usage Patterns

### Append-Only Log

```rust
use anyhow::Result;
use libblockchain::blockchain::BlockChain;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct LogEntry {
    timestamp: u64,
    user_id: String,
    action: String,
}

fn log_action(chain: &BlockChain, entry: LogEntry) -> Result<u64> {
    let bytes = serde_json::to_vec(&entry)?;
    chain.put_block(bytes, b"log-signature".to_vec())
}
```

### Latest Block

```rust
use anyhow::Result;
use libblockchain::block::Block;
use libblockchain::blockchain::BlockChain;

fn latest_block(chain: &BlockChain) -> Result<Option<(Block, Vec<u8>)>> {
    let count = chain.block_count()?;
    if count == 0 {
        return Ok(None);
    }

    let (block, signature) = chain.get_block_by_height(count - 1);
    Ok(Some((block?, signature?)))
}
```

### Custom Payloads

```rust
use anyhow::Result;
use libblockchain::blockchain::BlockChain;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Transaction {
    from: String,
    to: String,
    amount: u64,
}

fn store_transaction(chain: &BlockChain) -> Result<()> {
    let tx = Transaction {
        from: "Alice".to_string(),
        to: "Bob".to_string(),
        amount: 100,
    };

    let bytes = serde_json::to_vec(&tx)?;
    chain.put_block(bytes, b"tx-signature".to_vec())?;
    Ok(())
}
```

## Error Handling Notes

All blockchain operations return `anyhow::Result<T>`.

Common errors:

- opening the database fails because RocksDB cannot initialize or the path is invalid
- `get_block_by_height()` fails because the height is missing or corrupted
- `put_block()` fails because the payload exceeds `MAX_BLOCK_SIZE`
- validation fails because the hash chain, timestamp ordering, or signature presence is invalid

Bounds checking is still the caller's responsibility:

```rust
use anyhow::{Result, anyhow};
use libblockchain::blockchain::BlockChain;

fn read_block(chain: &BlockChain, height: u64) -> Result<Vec<u8>> {
    let count = chain.block_count()?;
    if height >= count {
        return Err(anyhow!("Block {} does not exist", height));
    }

    let (block, _) = chain.get_block_by_height(height);
    Ok(block?.block_data())
}
```

## Security Notes

- block data is stored as plaintext unless the application encrypts it first
- the library verifies signature presence, not signature cryptography
- filesystem permissions remain the primary access control boundary
- `put_block()` auto-validates each appended block

## Performance Notes

- reuse a single open chain instead of reopening the database repeatedly
- clone the handle for concurrent work instead of opening extra blockchain instances
- use `validate()` for routine checks and `validate_full()` only when you need a full scan

## Raw RocksDB Configuration

`RocksDbModel` still supports raw database configuration and exposes both:

- `open()` for the regular `rocksdb::DB` wrapper
- `open_multi_threaded()` for `DBWithThreadMode<MultiThreaded>`

```rust
use libblockchain::db_model::{CompressionType, RocksDbModel};

let db = RocksDbModel::new("./custom_db")
    .with_block_cache_size_mb(1024)
    .with_write_buffer_size_mb(128)
    .with_compression(CompressionType::Zstd)
    .with_column_family("blocks")
    .with_column_family("signatures")
    .open_multi_threaded()?;

let _ = db;
```

## Quick Reference

```rust
open_chain(path: &str) -> Result<BlockChain>
BlockChain::open(path: &str) -> Result<BlockChain>

.block_count() -> Result<u64>
.get_block_by_height(height: u64) -> (Result<Block>, Result<Vec<u8>>)
.get_signature_by_height(height: u64) -> Result<Vec<u8>>
.put_block(data: Vec<u8>, signature: Vec<u8>) -> Result<u64>
.put_signature(height: u64, signature: Vec<u8>) -> Result<u64>
.delete_last_block() -> Result<Option<u64>>
.validate() -> Result<()>
.validate_full() -> Result<()>
.validate_incremental() -> Result<u64>
```

## Build And Validation

```bash
cargo check
cargo test
cargo clippy
```

## Limitations

1. The blockchain API currently exposes only the shared read/write mode.
2. `get_block_by_height()` returns block and signature as separate `Result` values rather than a single struct.
3. There is no iterator helper in the current blockchain wrapper.
4. Signature verification is application-specific and not implemented by the library.
5. Data encryption is not built in.
