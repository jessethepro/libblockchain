# Copilot Instructions for libblockchain

## Project Overview
This is a **generic blockchain library** for creating and managing blockchain blocks. The actual data stored in `block_data` is application-specific and will be defined by consumer projects. This library provides the core block structure, hashing, and chain integrity primitives.

## Architecture

### Core Components
- **`src/block.rs`**: Defines `Block` and `BlockHeader` structures
  - `BlockHeader`: Contains cryptographically relevant data (version, parent_hash, timestamp, nonce)
  - `Block`: Represents a complete block with header, hash, data payload, and signature
  - Block height is intentionally **database metadata**, not part of the header structure

### Key Design Decisions
- **Data-agnostic**: `block_data: Vec<u8>` is opaque to this library - consumer projects define the payload
- **Separation of concerns**: Cryptographic data lives in `BlockHeader`; operational metadata (like height) is external
- **Hash duplication**: Both `block_hash` and `previous_block_hash` exist in `Block` for convenience, though `previous_block_hash` duplicates `block_header.parent_hash`

## Code Conventions

### Data Types
- Use `[u8; 32]` for all hash values (256-bit hashes)
- Use `Vec<u8>` for variable-length data (signatures, block payloads)
- Unix timestamps are `u64` (seconds since epoch)

### Module References (Currently Incomplete)
The codebase references modules that don't exist yet:
- `crate::blockchain::{H256, Signature}` - type aliases expected
- `crate::crypto::certificate::CertificateForBlockchain` - will be removed (certificate-specific, not generic)

### Dependencies
Current `Cargo.toml` is minimal. Expected dependencies based on code:
- `serde` + `serde_derive` - serialization
- `chrono` - timestamp handling  
- `rand` - nonce generation

## Development Workflow

### Build & Test
```bash
cargo build          # Compile library
cargo test           # Run tests
cargo check          # Fast compilation check
cargo doc --open     # Generate and view documentation
```

### Code Organization
- Keep library code in `src/lib.rs` minimal - re-export main types
- Each major concept gets its own module file (block, chain, crypto, etc.)
- Use `//!` module-level docs to explain the "why" behind design choices

## When Adding Features

### For New Block Types or Fields
- Add fields to `BlockHeader` only if they're cryptographically relevant (affect hash)
- Add to `Block` if they're metadata or derived values
- Update `BLOCK_VERSION` constant if making breaking changes to header structure

### For Cryptographic Operations
- **Hashing**: Use the `BlockHasher` trait (defined in `src/traits.rs`) for all hash operations
  - Consumers implement this trait with their chosen algorithm (SHA-256, BLAKE3, etc.)
  - Returns `Vec<u8>` to support variable-length hashes
  - Hash calculations should include serialized `BlockHeader` + `block_data`
- **Signatures**: Verification is the consumer's responsibility (they know the signature scheme)
- All cryptographic primitives should be generic/configurable through traits

### Testing Strategy
- Unit tests for each block component (header creation, serialization)
- Property tests for hash chain integrity
- Example integration showing how consumers would use the library

## Common Pitfalls
- Don't assume specific data formats in `block_data` - keep it generic
- Don't hardcode cryptographic algorithms - allow consumer configuration
- Remember: block height is NOT in the header (stored externally in database)
