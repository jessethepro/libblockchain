# AI Agent Integration Guide for libblockchain

**Target Audience**: AI coding agents integrating libblockchain into external projects  
**Library Version**: 0.1.0  
**Last Updated**: January 2026

## Quick Start

### Adding Dependency

```toml
# Cargo.toml
[dependencies]
libblockchain = { path = "../path/to/libblockchain" }
# OR from git:
# libblockchain = { git = "https://github.com/yourusername/libblockchain" }

anyhow = "1.0"  # For error handling
```

### Minimal Working Example

```rust
use libblockchain::blockchain::open_read_write_chain;
use anyhow::Result;

fn main() -> Result<()> {
    // Create or open blockchain
    let chain = open_read_write_chain("./my_blockchain".into())?;
    
    // Insert blocks (auto-validated, max 100MB each)
    let height0 = chain.put_block(b"Genesis data".to_vec())?;
    let height1 = chain.put_block(b"Block 1 data".to_vec())?;
    
    // Query blocks
    let block = chain.get_block_by_height(0)?;
    println!("Block 0: {:?}", block.block_data());
    
    // Iterate over all blocks
    for block_result in chain.iter()? {
        let block = block_result?;
        println!("Block {}: {:?}", block.height(), block.block_data());
    }
    
    // Validate integrity (incremental - fast)
    chain.validate()?;
    
    Ok(())
}
```

## Core Concepts

### Type-State Pattern

The library uses compile-time type states to enforce read-only vs read-write access:

```rust
use libblockchain::blockchain::{BlockChain, OpenChain, ReadOnly, ReadWrite};

// Opening states
let open_chain = BlockChain::<OpenChain>::open(path)?;
// OR
let open_chain = BlockChain::<OpenChain>::open_or_create(path)?;

// Convert to specific mode
let ro_chain = BlockChain::<ReadOnly>::open_read_only(open_chain)?;
let rw_chain = BlockChain::<ReadWrite>::open_read_write(open_chain)?;

// Helper functions (recommended)
let ro = open_read_only_chain(path)?;        // open() + open_read_only()
let rw = open_read_write_chain(path, true)?; // open_or_create() + open_read_write()
```

**ReadOnly operations:**
- `block_count() -> Result<u64>`
- `get_block_by_height(height: u64) -> Result<Block>`
- `get_signature_by_height(height: u64) -> Result<Vec<u8>>`
- `validate() -> Result<()>` - Incremental validation (fast)
- `validate_full() -> Result<()>` - Full O(n) validation
- `validate_incremental() -> Result<u64>` - Returns validated height
- `iter() -> Result<BlockIterator>` - Iterator over all blocks

**ReadWrite operations (includes all ReadOnly operations):**
- `put_block(data: Vec<u8>) -> Result<u64>` - Max 100MB, auto-validates
- `put_signature(height: u64, sig: Vec<u8>) -> Result<u64>`
- `delete_last_block() -> Result<Option<u64>>`
- `validate()` - Incremental validation with cache update
- `validate_full()` - Full blockchain validation
- `validate_incremental() -> Result<u64>` - Validate new blocks, update cache

### Block Structure

```rust
use libblockchain::block::Block;

// Blocks are automatically created by put_block()
let height = chain.put_block(your_data)?;

// Retrieve and inspect blocks
let block = chain.get_block_by_height(height)?;

// Block accessors
block.height();           // u64 - Sequential block number (0-indexed)
block.block_hash();       // Vec<u8> - 64-byte SHA-512 hash
block.parent_hash();      // Vec<u8> - Parent's block_hash (or [0; 64] for genesis)
block.block_data();       // Vec<u8> - Your application data (plaintext)
block.bytes();            // Vec<u8> - Serialized block for storage
```

## Common Usage Patterns

### Pattern 1: Simple Append-Only Log

```rust
use libblockchain::blockchain::open_read_write_chain;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct LogEntry {
    timestamp: u64,
    user_id: String,
    action: String,
}

fn log_action(chain: &BlockChain<ReadWrite>, entry: LogEntry) -> Result<u64> {
    let json = serde_json::to_vec(&entry)?;
    chain.put_block(json)
}

fn get_log_entry(chain: &BlockChain<ReadOnly>, height: u64) -> Result<LogEntry> {
    let block = chain.get_block_by_height(height)?;
    let entry: LogEntry = serde_json::from_slice(&block.block_data())?;
    Ok(entry)
}
```

### Pattern 2: Iterating All Blocks

```rust
// Use the iterator (more efficient than manual loops)
fn process_all_blocks(chain: &BlockChain<ReadOnly>) -> Result<()> {
    for block_result in chain.iter()? {
        let block = block_result?;
        println!("Block {}: {} bytes", block.height(), block.block_data().len());
        // Process block.block_data() as needed
    }
    
    Ok(())
}

// Or use iterator methods
fn calculate_total_size(chain: &BlockChain<ReadOnly>) -> Result<usize> {
    let total: usize = chain.iter()?
        .map(|b| b.ok().map(|block| block.block_data().len()).unwrap_or(0))
        .sum();
    Ok(total)
}
```

### Pattern 3: Get Latest Block

```rust
fn get_latest_block(chain: &BlockChain<ReadOnly>) -> Result<Option<Block>> {
    let count = chain.block_count()?;
    
    if count == 0 {
        return Ok(None);
    }
    
    let latest = chain.get_block_by_height(count - 1)?;
    Ok(Some(latest))
}
```

### Pattern 4: Block Size Validation

```rust
use libblockchain::blockchain::MAX_BLOCK_SIZE;

fn add_block_if_valid(
    chain: &BlockChain<ReadWrite>,
    data: Vec<u8>,
) -> Result<u64> {
    // Size validation (automatic, but can check early)
    if data.is_empty() {
        return Err(anyhow!("Cannot add empty block"));
    }
    
    if data.len() > MAX_BLOCK_SIZE {
        return Err(anyhow!("Block too large: {} bytes (max: {})", 
            data.len(), MAX_BLOCK_SIZE));
    }
    
    // Insert with auto-validation
    let height = chain.put_block(data)?;
    
    Ok(height)
}
```

### Pattern 5: Digital Signatures

```rust
fn sign_and_store_block(
    chain: &BlockChain<ReadWrite>,
    data: Vec<u8>,
    signing_fn: impl FnOnce(&[u8]) -> Vec<u8>,
) -> Result<u64> {
    // Insert block first
    let height = chain.put_block(data)?;
    
    // Get the block to sign its hash
    let block = chain.get_block_by_height(height)?;
    let signature = signing_fn(&block.block_hash());
    
    // Store signature
    chain.put_signature(height, signature)?;
    
    Ok(height)
}

fn verify_block_signature(
    chain: &BlockChain<ReadOnly>,
    height: u64,
    verify_fn: impl FnOnce(&[u8], &[u8]) -> bool,
) -> Result<bool> {
    let block = chain.get_block_by_height(height)?;
    let sig = chain.get_signature_by_height(height)?
        .ok_or_else(|| anyhow!("No signature for block {}", height))?;
    
    Ok(verify_fn(&block.block_hash(), &sig))
}
```

## Error Handling

All operations return `anyhow::Result<T>`. Common error scenarios:

```rust
use anyhow::{Context, Result};

fn safe_operation(path: PathBuf, height: u64) -> Result<Vec<u8>> {
    // Database doesn't exist
    let chain = open_read_only_chain(path.clone())
        .context("Failed to open blockchain - does it exist?")?;
    
    // Block height out of range
    let count = chain.block_count()?;
    if height >= count {
        return Err(anyhow!(
            "Block {} doesn't exist (chain has {} blocks)",
            height,
            count
        ));
    }
    
    // Get block (could fail on corruption)
    let block = chain.get_block_by_height(height)
        .context(format!("Failed to retrieve block {}", height))?;
    
    Ok(block.block_data())
}
```

**Common Error Types:**
- **Database not found**: `open()` fails if path doesn't exist (use `open_or_create()`)
- **Corruption**: `get_block_by_height()` fails if stored data is invalid
- **Height out of range**: No validation - you must check `block_count()` first
- **Block size exceeded**: `put_block()` fails if data > 100MB
- **Validation failure**: `validate()` fails if parent hashes don't match or timestamps invalid

## Security Considerations

### ⚠️ Critical Security Warnings

1. **NO ENCRYPTION**: All data stored as plaintext in RocksDB
   ```rust
   // ❌ DON'T store sensitive data directly
   chain.put_block(b"password123".to_vec())?;
   
   // ✅ DO encrypt before storing
   let encrypted = your_encryption_fn(b"password123")?;
   chain.put_block(encrypted)?;
   ```

2. **NO ACCESS CONTROL**: Filesystem permissions are the only protection
   - Anyone with read access can dump entire chain
   - Anyone with write access can corrupt database
   - Use OS-level file permissions for security

3. **TIMESTAMP MANIPULATION**: `SystemTime` can be manipulated
   ```rust
   // Block timestamps are NOT trusted for security
   // Validation checks timestamps but attacker with system access can bypass
   // Use block height for ordering, not timestamps
   let block = chain.get_block_by_height(height)?;
   // block.timestamp() can be manipulated during insertion
   ```

4. **BLOCK SIZE LIMIT**: 100MB maximum enforced
   ```rust
   // Automatic enforcement
   let large_data = vec![0u8; 101 * 1024 * 1024];
   chain.put_block(large_data)?;  // Error: exceeds maximum size
   ```

5. **NO NETWORK VALIDATION**: This is purely local storage
   - No consensus mechanism
   - No proof-of-work
   - No Byzantine fault tolerance
   - Not suitable for distributed/multi-node setups without additional layers

6. **VALIDATION IS AUTO**: `put_block()` validates automatically
   ```rust
   // Auto-validation with incremental cache
   chain.put_block(data)?;  // Validates new block automatically
   ```

### Recommended Security Practices

```rust
// 1. Encrypt sensitive data at application layer
fn store_encrypted(chain: &BlockChain<ReadWrite>, plaintext: &[u8]) -> Result<u64> {
    let encrypted = encrypt(plaintext)?; // Your encryption
    chain.put_block(encrypted)
}

// 2. Set strict filesystem permissions
use std::fs;
use std::os::unix::fs::PermissionsExt;

let metadata = fs::metadata(&db_path)?;
let mut permissions = metadata.permissions();
permissions.set_mode(0o600); // Owner read/write only
fs::set_permissions(&db_path, permissions)?;

// 3. Validate on open
let chain = open_read_only_chain(path)?;
chain.validate().context("Blockchain integrity check failed")?;

// 4. Don't trust timestamps for security decisions
// Use block height for ordering instead
```

## Performance Tips

### Database Configuration

```rust
use libblockchain::db_model::RocksDbModel;

// High-performance preset (default for read-write)
// - 512MB block cache
// - 64MB write buffer
// - LZ4 compression

// High-durability preset
// - Frequent flushes
// - Paranoid checks
// Use: Manually configure RocksDbModel in blockchain.rs

// Read-only preset (default for read-only)
// - No write buffers
// - Optimized for reads
```

### Best Practices

```rust
// ✅ DO: Use iterator for traversal
for block in chain.iter()? {
    process_block(block?)?;
}

// ❌ DON'T: Manual loop (less efficient, more code)
for height in 0..chain.block_count()? {
    process_block(chain.get_block_by_height(height)?)?;
}

// ✅ DO: Use incremental validation (6x faster)
chain.validate()?;  // or validate_incremental()

// ❌ DON'T: Use full validation unnecessarily
chain.validate_full()?;  // Only when you need to re-validate everything

// ✅ DO: Reuse connection
let chain = open_read_write_chain(path, true)?;
for data in &data_items {
    chain.put_block(data.clone())?;
}

// ❌ DON'T: Open/close repeatedly
for data in &data_items {
    let chain = open_read_write_chain(path.clone(), true)?; // Slow!
    chain.put_block(data.clone())?;
    // chain closed here
}

// ✅ DO: Blocks auto-validate on insert
chain.put_block(data)?;  // Validation happens automatically

// ❌ DON'T: Manually validate after each insert
chain.put_block(data)?;
chain.validate()?;  // Unnecessary - already done in put_block()
```

### Thread Safety

**⚠️ NOT THREAD-SAFE**: Database uses `SingleThreaded` mode

```rust
// ❌ DON'T: Share across threads
let chain = open_read_write_chain(path, true)?;
std::thread::spawn(move || {
    chain.put_block(data)?; // COMPILE ERROR or CRASH
});

// ✅ DO: Use separate connections per thread
// Each thread opens its own connection
std::thread::spawn(move || {
    let chain = open_read_write_chain(path.clone(), false)?;
    chain.put_block(data)?;
    Ok::<_, anyhow::Error>(())
});
```

## Build Configuration

### Required Features

```toml
# Your project's Cargo.toml
[dependencies]
libblockchain = { path = "../libblockchain" }

# libblockchain's dependencies (automatically included):
# - rocksdb = "0.24" with features = ["mt_static"]
# - openssl = "0.10" with features = ["vendored"]
# - anyhow = "1.0"
# - uuid = "1.11" with features = ["v4"]
```

### Build Requirements

**Linux** (primary platform):
- C++ compiler (g++ or clang)
- CMake (3.10+)
- make
- First build: 5-10 minutes (compiles RocksDB + OpenSSL from source)

**macOS**:
- Xcode command line tools
- CMake via Homebrew: `brew install cmake`

**Windows**:
- Not officially tested
- Requires Visual Studio C++ build tools
- May have compatibility issues with vendored builds

### Compile-Time Checks

```bash
cargo check   # Fast type checking
cargo build   # Full compilation
cargo clippy  # Lint warnings (unwrap_used, indexing_slicing enabled)
```

## Troubleshooting

### Problem: "Failed to open RocksDB"

```rust
// Error: Database doesn't exist
let chain = open_read_only_chain(path)?; // Fails if missing

// Solutions:
// 1. Check if database exists first
if !path.exists() {
    return Err(anyhow!("Database not found at {:?}", path));
}

// 2. Use open_or_create for read-write
let chain = open_read_write_chain(path, true)?; // Creates if missing

// 3. Create explicitly
use libblockchain::blockchain::{BlockChain, OpenChain};
let open_chain = BlockChain::<OpenChain>::open_or_create(path)?;
```

### Problem: "Block height out of range"

```rust
// ❌ No automatic bounds checking
let block = chain.get_block_by_height(999)?; // Panics or errors

// ✅ Always check bounds
let count = chain.block_count()?;
if height < count {
    let block = chain.get_block_by_height(height)?;
} else {
    return Err(anyhow!("Block {} doesn't exist", height));
}
```

### Problem: "Validation failed"

```rust
// Chain has broken parent hash links
chain.validate()?; // Error: Block at height X has invalid parent hash

// Causes:
// - Database corruption
// - Manual file modification
// - Incomplete writes
// - Bug in library (report if reproducible)

// Recovery:
// - No built-in repair
// - Restore from backup
// - Delete corrupted blocks with delete_last_block()
```

### Problem: "System time error"

```rust
// Timestamp generation failed (rare)
chain.put_block(data)?; // Error: System time error

// Cause: System clock before Unix epoch (1970-01-01)
// Solution: Fix system clock or file an issue to remove timestamp dependency
```

## Complete Example: Transaction Log

```rust
use libblockchain::blockchain::{open_read_write_chain, BlockChain, ReadOnly};
use anyhow::Result;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
struct Transaction {
    from: String,
    to: String,
    amount: u64,
}

fn main() -> Result<()> {
    let db_path = "./transaction_log".into();
    
    // Initialize blockchain
    let chain = open_read_write_chain(db_path, true)?;
    
    // Add transactions
    let tx1 = Transaction {
        from: "Alice".to_string(),
        to: "Bob".to_string(),
        amount: 100,
    };
    add_transaction(&chain, &tx1)?;
    
    let tx2 = Transaction {
        from: "Bob".to_string(),
        to: "Charlie".to_string(),
        amount: 50,
    };
    add_transaction(&chain, &tx2)?;
    
    // Validate integrity
    chain.validate()?;
    
    // Query transactions
    let count = chain.block_count()?;
    println!("Total transactions: {}", count);
    
    for height in 0..count {
        let tx = get_transaction(&chain, height)?;
        println!("Block {}: {:?}", height, tx);
    }
    
    Ok(())
}

fn add_transaction(
    chain: &BlockChain<impl libblockchain::blockchain::Mode>,
    tx: &Transaction,
) -> Result<u64> {
    let json = serde_json::to_vec(tx)?;
    chain.put_block(json)
}

fn get_transaction(
    chain: &BlockChain<impl libblockchain::blockchain::Mode>,
    height: u64,
) -> Result<Transaction> {
    let block = chain.get_block_by_height(height)?;
    let tx: Transaction = serde_json::from_slice(&block.block_data())?;
    Ok(tx)
}
```

## API Quick Reference

### Opening Blockchain
```rust
open_read_only_chain(path: PathBuf) -> Result<BlockChain<ReadOnly>>
open_read_write_chain(path: PathBuf) -> Result<BlockChain<ReadWrite>>
```

### Constants
```rust
MAX_BLOCK_SIZE: usize = 104_857_600  // 100MB maximum block size
```

### ReadOnly Methods
```rust
.block_count() -> Result<u64>
.get_block_by_height(height: u64) -> Result<Block>
.get_signature_by_height(height: u64) -> Result<Vec<u8>>
.validate() -> Result<()>                      // Incremental validation
.validate_full() -> Result<()>                 // Full O(n) validation
.validate_incremental() -> Result<u64>         // Returns validated height
.iter() -> Result<BlockIterator>               // Iterator over blocks
```

### ReadWrite Methods (includes ReadOnly)
```rust
.put_block(data: Vec<u8>) -> Result<u64>       // Max 100MB, auto-validates
.put_signature(height: u64, sig: Vec<u8>) -> Result<u64>
.delete_last_block() -> Result<Option<u64>>
// Plus all ReadOnly methods
```

### Block Methods
```rust
.height() -> u64
.block_hash() -> Vec<u8>              // 64 bytes (SHA-512)
.parent_hash() -> Vec<u8>             // 64 bytes
.block_data() -> Vec<u8>              // Your application data
.bytes() -> Vec<u8>                   // Serialized format
Block::from_bytes(&[u8]) -> Result<Block>
```

## Additional Resources

- **API Documentation**: Run `cargo doc --open` in library directory
- **Source Code**: [/home/jessethepro/sandbox/libblockchain](file:///home/jessethepro/sandbox/libblockchain)
- **AI Agent Instructions**: `.github/copilot-instructions.md` (internal development guide)
- **Changelog**: `CHANGELOG.md` for version history

## Version Compatibility

- **Current Version**: 0.1.0
- **Rust Edition**: 2024 (requires Rust 1.85+)
- **Stability**: API may change in 0.x versions
- **Serialization Format**: 100-byte BlockHeader, compatible with future 0.x versions unless BLOCK_VERSION increments

## Known Limitations

1. **No thread safety**: SingleThreaded RocksDB mode
2. **No encryption**: Application must encrypt data before storage
3. **No network layer**: Purely local persistence
4. **No consensus**: Not suitable for distributed systems without additional layers
5. **Limited timestamp validation**: Checks but can't prevent system clock manipulation
6. **No backups**: Manual backup of database directory required
7. **100MB block size limit**: Hard-coded maximum (can be modified in source)
