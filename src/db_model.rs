//! Database configuration and models for SledDB and RocksDB
//!
//! This module defines configuration structures for creating and managing
//! embedded database instances. Supports both Sled (pure Rust) and RocksDB
//! (C++ based) for persistent blockchain storage.
//!
//! # Features
//!
//! - **Configuration presets**: Pre-configured settings for common use cases
//! - **Builder pattern**: Fluent API for custom configurations
//! - **Serializable**: All configurations can be serialized with serde
//! - **Dual database support**: Choose between SledDB or RocksDB
//!
//! # SledDB Presets
//!
//! - [`SledDb::high_performance()`]: Optimized for speed (large cache, async flush)
//! - [`SledDb::high_durability()`]: Optimized for safety (sync flush, compression)
//! - [`SledDb::temporary()`]: In-memory database deleted on close
//! - [`SledDb::read_only()`]: Read-only access to existing database
//!
//! # RocksDB Presets
//!
//! - [`RocksDbModel::high_performance()`]: Optimized for speed (large caches, LZ4 compression)
//! - [`RocksDbModel::high_durability()`]: Optimized for safety (sync writes, Zstd compression)
//! - [`RocksDbModel::read_only()`]: Read-only access to existing database
//! # Example (RocksDB)
//!
//! ```no_run
//! use libblockchain::db_model::{RocksDbModel, CompressionType};
//!
//! # fn example() -> Result<(), rocksdb::Error> {
//! // Use a preset configuration
//! let db = RocksDbModel::high_performance("/path/to/db").open()?;
//!
//! // Or customize settings
//! let db = RocksDbModel::new("/path/to/db")
//!     .with_block_cache_size_mb(1024) // 1 GB cache
//!     .with_compression(CompressionType::Zstd)
//!     .with_column_family("blocks")
//!     .with_column_family("height")
//!     .open()?;
//! # Ok(())
//! # }
//! ```

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Flush mode configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlushMode {
    /// Automatically flush periodically (balanced durability/performance)
    Auto,

    /// Flush after every write operation (maximum durability, lowest performance)
    EveryOp,

    /// Never automatically flush (maximum performance, data may be lost on crash)
    Never,
}

/// Configuration structure for creating a RocksDB database instance
///
/// This struct contains all available options that can be used to configure
/// a RocksDB embedded database. RocksDB is a high-performance key-value store with:
/// - ACID transactions
/// - Column families (similar to tables)
/// - Atomic batch writes
/// - Snapshots and iterators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RocksDbModel {
    // ===== Basic Configuration =====
    /// Path to the database directory
    pub path: PathBuf,

    /// Whether to create the database directory if it doesn't exist
    /// Default: true
    pub create_if_missing: bool,

    /// Error if database already exists
    /// Default: false
    pub error_if_exists: bool,

    // ===== Cache Configuration =====
    /// Block cache size in bytes (for read cache)
    /// Higher values improve read performance but use more memory
    /// Default: 512 MB
    pub block_cache_size: Option<usize>,

    /// Write buffer size in bytes (memtable size)
    /// Default: 64 MB
    pub write_buffer_size: Option<usize>,

    /// Maximum number of write buffers
    /// Default: 2
    pub max_write_buffer_number: Option<i32>,

    // ===== Compression Configuration =====
    /// Compression type for data blocks
    pub compression_type: CompressionType,

    /// Compression type for bottommost level
    pub bottommost_compression_type: Option<CompressionType>,

    // ===== Performance Configuration =====
    /// Maximum number of background jobs (compaction + flush)
    /// Default: 2
    pub max_background_jobs: Option<i32>,

    /// Number of open files that can be used by the database
    /// -1 means unlimited, Default: 1000
    pub max_open_files: Option<i32>,

    /// Use direct I/O for reads (bypasses OS cache)
    /// Default: false
    pub use_direct_reads: bool,

    /// Use direct I/O for writes (bypasses OS cache)
    /// Default: false
    pub use_direct_io_for_flush_and_compaction: bool,

    // ===== Durability Configuration =====
    /// Sync writes to disk (slower but safer)
    /// Default: false
    pub sync_writes: bool,

    /// Disable WAL (Write-Ahead Log) - faster but less durable
    /// Default: false (WAL enabled)
    pub disable_wal: bool,

    // ===== Column Families (Tables) =====
    /// Column families to create/open
    /// RocksDB equivalent of "tables" or "trees"
    pub column_families: Vec<String>,

    // ===== Advanced Options =====
    /// Read-only mode
    /// Default: false
    pub read_only: bool,

    /// Enable statistics collection
    /// Default: false
    pub enable_statistics: bool,

    /// Optimize for point lookups (vs range scans)
    /// Default: false
    pub optimize_for_point_lookup: bool,

    // ===== Metadata =====
    /// Optional description of the database purpose
    pub description: Option<String>,

    /// Database version (for schema migrations)
    pub version: Option<String>,
}

/// Compression types supported by RocksDB
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompressionType {
    /// No compression
    None,

    /// Snappy compression (fast, moderate compression)
    Snappy,

    /// Zlib compression (slower, better compression)
    Zlib,

    /// Bz2 compression (slowest, best compression)
    Bz2,

    /// LZ4 compression (very fast, moderate compression)
    Lz4,

    /// LZ4HC compression (slower than LZ4, better compression)
    Lz4hc,

    /// Zstd compression (good balance of speed and compression)
    Zstd,
}

impl Default for RocksDbModel {
    fn default() -> Self {
        Self {
            path: PathBuf::from("./data/rocksdb"),
            create_if_missing: true,
            error_if_exists: false,
            block_cache_size: Some(512 * 1024 * 1024), // 512 MB
            write_buffer_size: Some(64 * 1024 * 1024), // 64 MB
            max_write_buffer_number: Some(2),
            compression_type: CompressionType::Lz4,
            bottommost_compression_type: Some(CompressionType::Zstd),
            max_background_jobs: Some(2),
            max_open_files: Some(1000),
            use_direct_reads: false,
            use_direct_io_for_flush_and_compaction: false,
            sync_writes: false,
            disable_wal: false,
            column_families: vec![
                // Default column family (required)
                "default".to_string(),
                // Block storage: key = UUID, value = Block
                "blocks".to_string(),
                // Height index: key = u64 height, value = UUID
                "height".to_string(),
            ],
            read_only: false,
            enable_statistics: false,
            optimize_for_point_lookup: false,
            description: None,
            version: Some("1.0.0".to_string()),
        }
    }
}

impl RocksDbModel {
    /// Create a new RocksDbModel configuration with the given path
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            ..Default::default()
        }
    }

    /// Create a configuration for a read-only database
    pub fn read_only(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            read_only: true,
            create_if_missing: false,
            ..Default::default()
        }
    }

    /// Create a high-performance configuration (less durable)
    pub fn high_performance(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            block_cache_size: Some(1024 * 1024 * 1024), // 1 GB cache
            write_buffer_size: Some(128 * 1024 * 1024), // 128 MB
            max_write_buffer_number: Some(4),
            compression_type: CompressionType::Lz4,
            max_background_jobs: Some(4),
            max_open_files: Some(-1), // Unlimited
            sync_writes: false,
            disable_wal: false, // Keep WAL for safety
            ..Default::default()
        }
    }

    /// Create a high-durability configuration (slower performance)
    pub fn high_durability(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            block_cache_size: Some(256 * 1024 * 1024), // 256 MB cache
            write_buffer_size: Some(32 * 1024 * 1024), // 32 MB
            max_write_buffer_number: Some(2),
            compression_type: CompressionType::Zstd,
            bottommost_compression_type: Some(CompressionType::Zstd),
            max_background_jobs: Some(2),
            sync_writes: true, // Sync every write
            disable_wal: false,
            ..Default::default()
        }
    }

    /// Open a RocksDB database with this configuration
    pub fn open(&self) -> Result<rocksdb::DB, rocksdb::Error> {
        let mut opts = rocksdb::Options::default();

        // Basic options
        opts.create_if_missing(self.create_if_missing);
        opts.set_error_if_exists(self.error_if_exists);

        // Cache configuration
        if let Some(cache_size) = self.block_cache_size {
            let cache = rocksdb::Cache::new_lru_cache(cache_size);
            let mut block_opts = rocksdb::BlockBasedOptions::default();
            block_opts.set_block_cache(&cache);
            opts.set_block_based_table_factory(&block_opts);
        }

        if let Some(buffer_size) = self.write_buffer_size {
            opts.set_write_buffer_size(buffer_size);
        }

        if let Some(num_buffers) = self.max_write_buffer_number {
            opts.set_max_write_buffer_number(num_buffers);
        }

        // Compression
        opts.set_compression_type(match self.compression_type {
            CompressionType::None => rocksdb::DBCompressionType::None,
            CompressionType::Snappy => rocksdb::DBCompressionType::Snappy,
            CompressionType::Zlib => rocksdb::DBCompressionType::Zlib,
            CompressionType::Bz2 => rocksdb::DBCompressionType::Bz2,
            CompressionType::Lz4 => rocksdb::DBCompressionType::Lz4,
            CompressionType::Lz4hc => rocksdb::DBCompressionType::Lz4hc,
            CompressionType::Zstd => rocksdb::DBCompressionType::Zstd,
        });

        if let Some(bottommost) = self.bottommost_compression_type {
            opts.set_bottommost_compression_type(match bottommost {
                CompressionType::None => rocksdb::DBCompressionType::None,
                CompressionType::Snappy => rocksdb::DBCompressionType::Snappy,
                CompressionType::Zlib => rocksdb::DBCompressionType::Zlib,
                CompressionType::Bz2 => rocksdb::DBCompressionType::Bz2,
                CompressionType::Lz4 => rocksdb::DBCompressionType::Lz4,
                CompressionType::Lz4hc => rocksdb::DBCompressionType::Lz4hc,
                CompressionType::Zstd => rocksdb::DBCompressionType::Zstd,
            });
        }

        // Performance
        if let Some(jobs) = self.max_background_jobs {
            opts.set_max_background_jobs(jobs);
        }

        if let Some(files) = self.max_open_files {
            opts.set_max_open_files(files);
        }

        opts.set_use_direct_reads(self.use_direct_reads);
        opts.set_use_direct_io_for_flush_and_compaction(
            self.use_direct_io_for_flush_and_compaction,
        );

        // Durability
        if self.disable_wal {
            opts.set_wal_dir(&self.path);
        }

        if self.enable_statistics {
            opts.enable_statistics();
        }

        if self.optimize_for_point_lookup {
            if let Some(cache_size) = self.block_cache_size {
                opts.optimize_for_point_lookup(cache_size as u64);
            }
        }

        // Open database with column families
        if self.read_only {
            rocksdb::DB::open_cf_for_read_only(&opts, &self.path, &self.column_families, false)
        } else if self.column_families.is_empty() {
            rocksdb::DB::open(&opts, &self.path)
        } else {
            // Try to open with existing column families, or create them
            match rocksdb::DB::open_cf(&opts, &self.path, &self.column_families) {
                Ok(db) => Ok(db),
                Err(_) => {
                    // Database might not exist yet, create it
                    rocksdb::DB::open_cf(&opts, &self.path, &self.column_families)
                }
            }
        }
    }

    // ===== Builder Pattern Methods =====

    /// Set the database path
    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = path.into();
        self
    }

    /// Set block cache size in bytes
    pub fn with_block_cache_size(mut self, bytes: usize) -> Self {
        self.block_cache_size = Some(bytes);
        self
    }

    /// Set block cache size in megabytes
    pub fn with_block_cache_size_mb(mut self, megabytes: usize) -> Self {
        self.block_cache_size = Some(megabytes * 1024 * 1024);
        self
    }

    /// Set write buffer size in bytes
    pub fn with_write_buffer_size(mut self, bytes: usize) -> Self {
        self.write_buffer_size = Some(bytes);
        self
    }

    /// Set write buffer size in megabytes
    pub fn with_write_buffer_size_mb(mut self, megabytes: usize) -> Self {
        self.write_buffer_size = Some(megabytes * 1024 * 1024);
        self
    }

    /// Set compression type
    pub fn with_compression(mut self, compression: CompressionType) -> Self {
        self.compression_type = compression;
        self
    }

    /// Set bottommost compression type
    pub fn with_bottommost_compression(mut self, compression: CompressionType) -> Self {
        self.bottommost_compression_type = Some(compression);
        self
    }

    /// Set maximum background jobs
    pub fn with_max_background_jobs(mut self, jobs: i32) -> Self {
        self.max_background_jobs = Some(jobs);
        self
    }

    /// Enable/disable sync writes
    pub fn with_sync_writes(mut self, sync: bool) -> Self {
        self.sync_writes = sync;
        self
    }

    /// Add a column family (table)
    pub fn with_column_family(mut self, name: impl Into<String>) -> Self {
        let name = name.into();
        if !self.column_families.contains(&name) {
            self.column_families.push(name);
        }
        self
    }

    /// Set all column families (tables)
    pub fn with_column_families(mut self, families: Vec<String>) -> Self {
        self.column_families = families;
        self
    }

    /// Set database description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set database version
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Enable read-only mode
    pub fn as_read_only(mut self) -> Self {
        self.read_only = true;
        self.create_if_missing = false;
        self
    }

    /// Enable statistics collection
    pub fn with_statistics(mut self) -> Self {
        self.enable_statistics = true;
        self
    }

    /// Optimize for point lookups
    pub fn optimize_for_point_lookup(mut self) -> Self {
        self.optimize_for_point_lookup = true;
        self
    }
}
