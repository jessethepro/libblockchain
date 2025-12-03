# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-12-03

### Added
- **AppKeyStore module**: Secure private key storage using `secrecy` crate
  - Automatic public key extraction from private keys
  - Support for PEM-encoded key files with optional password protection
  - Private keys automatically zeroed on drop
- **BlockChain::get_data_at_height()**: Decrypt block data at specific height
- **BlockChain::validate()**: Validate entire blockchain integrity
- **Block::get_block_data()**: Static method to decrypt block data
- SHA-512 hashing for all blocks (64-byte hashes)
- Comprehensive test suite: 29 unit tests, 6 integration tests, 8 doctests
- Full API documentation with examples

### Changed
- **BREAKING**: `BlockChain::new()` now requires `private_key_path` parameter
  - Old: `BlockChain::new(path)`
  - New: `BlockChain::new(path, private_key_path)`
- **BREAKING**: `insert_block()` no longer requires certificate parameter
  - Old: `insert_block(data, cert)`
  - New: `insert_block(data)`
- **BREAKING**: Replaced X509 certificate usage with direct `PKey<Public>` keys
  - `Block::new_genesis_block()` now takes `&PKey<Public>` instead of `X509`
  - `Block::new_regular_block()` now takes `&PKey<Public>` instead of `X509`
  - `hybrid_encrypt()` now takes `&PKey<Public>` instead of `X509`
- **BREAKING**: Changed hash size from 32 bytes (SHA-256) to 64 bytes (SHA-512)
  - `Block::block_hash` is now `[u8; 64]`
  - `BlockHeader::parent_hash` is now `[u8; 64]`
- **BREAKING**: `hybrid_decrypt()` signature changed
  - Old: `hybrid_decrypt(&private_key, &encrypted_data)`
  - New: `hybrid_decrypt(&private_key, encrypted_data)` (takes ownership)
- Updated all documentation examples to reflect new API
- Improved README with comprehensive usage examples

### Removed
- **BREAKING**: Removed `hybrid_decrypt_from_bytes()` function (use `hybrid_decrypt()`)
- **BREAKING**: Removed X509 certificate dependencies from public API
- Removed `HybridEncryptedData` struct from public API (now uses `Vec<u8>`)

### Security
- Private keys now protected with `secrecy` crate
- Automatic zeroing of sensitive key material
- SHA-512 for stronger hash integrity
- AES-256-GCM authenticated encryption with random nonces
- RSA-OAEP key encapsulation

### Fixed
- All compilation warnings resolved
- All tests passing (43 total tests)
- Documentation examples now compile correctly

## [Initial Development]

### Added
- Basic block structure with BlockHeader
- SledDB-backed persistent storage
- Hybrid RSA + AES-256-GCM encryption
- UUID-based block identification
- Automatic height management
- Block iterator support
- Database configuration presets
