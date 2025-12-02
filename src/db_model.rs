//! Database configuration and model for SledDB
//!
//! This module defines configuration structures for creating and managing
//! Sled embedded database instances. Sled is a high-performance, pure Rust
//! key-value store used for persistent blockchain storage.
//!
//! # Features
//!
//! - **Configuration presets**: Pre-configured settings for common use cases
//! - **Builder pattern**: Fluent API for custom configurations
//! - **Serializable**: All configurations can be serialized with serde
//!
//! # Presets
//!
//! - [`SledDb::high_performance()`]: Optimized for speed (large cache, async flush)
//! - [`SledDb::high_durability()`]: Optimized for safety (sync flush, compression)
//! - [`SledDb::temporary()`]: In-memory database deleted on close
//! - [`SledDb::read_only()`]: Read-only access to existing database
//!
//! # Example
//!
//! ```no_run
//! use libblockchain::db_model::SledDb;
//!
//! # fn example() -> std::io::Result<()> {
//! // Use a preset configuration
//! let db = SledDb::high_performance("/path/to/db").open()?;
//!
//! // Or customize settings
//! let db = SledDb::new("/path/to/db")
//!     .with_cache_capacity(1024 * 1024 * 1024) // 1 GB cache
//!     .with_flush_mode(libblockchain::db_model::FlushMode::Auto)
//!     .with_flush_every_ms(1000) // Flush every second
//!     .open()?;
//! # Ok(())
//! # }
//! ```

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration structure for creating a Sled database instance
/// 
/// This struct contains all available options that can be used to configure
/// a Sled embedded database. Sled is a pure Rust key-value store with:
/// - ACID transactions
/// - Zero-copy reads
/// - Lock-free operations
/// - Crash recovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SledDb {
    // ===== Basic Configuration =====
    
    /// Path to the database directory
    /// This is where Sled will store all database files
    pub path: PathBuf,
    
    /// Whether to create the database directory if it doesn't exist
    /// Default: true
    pub create_new: bool,
    
    // ===== Cache Configuration =====
    
    /// Cache capacity in bytes
    /// Higher values improve read performance but use more memory
    /// Default: 512 MB (536,870,912 bytes)
    pub cache_capacity: Option<u64>,
    
    /// Whether to use compression for stored data
    /// Reduces disk usage but adds CPU overhead
    /// Default: false (Sled uses zstd compression when enabled)
    pub use_compression: bool,
    
    /// Compression factor (1-22, where 22 is highest compression)
    /// Only used if use_compression is true
    /// Default: 5 (balanced between speed and compression ratio)
    pub compression_factor: Option<i32>,
    
    // ===== Durability & Performance =====
    
    /// Flush mode for durability
    /// - Auto: Flush periodically (balanced)
    /// - EveryOp: Flush after every operation (safest, slowest)
    /// - Never: Never flush automatically (fastest, least safe)
    pub flush_mode: FlushMode,
    
    /// Flush interval in milliseconds (only for Auto mode)
    /// How often to flush data to disk
    /// Default: 500ms
    pub flush_every_ms: Option<u64>,
    
    /// Segment size in bytes
    /// Size of each log segment file
    /// Larger = fewer files but longer recovery time
    /// Default: 512 MB
    pub segment_size: Option<usize>,
    
    // ===== Advanced Options =====
    
    /// Temporary mode - database deleted on close
    /// Useful for testing or ephemeral storage
    /// Default: false
    pub temporary: bool,
    
    /// Read-only mode
    /// Opens database without write permissions
    /// Default: false
    pub read_only: bool,
    
    /// Print profile information on drop
    /// Useful for debugging and performance analysis
    /// Default: false
    pub print_profile_on_drop: bool,
    
    // ===== Tree Configuration =====
    
    /// Default tree names to create on initialization
    /// Sled organizes data into "trees" (similar to tables)
    pub default_trees: Vec<String>,
    
    // ===== Metadata =====
    
    /// Optional description of the database purpose
    pub description: Option<String>,
    
    /// Database version (for schema migrations)
    pub version: Option<String>,
}

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

impl Default for SledDb {
    fn default() -> Self {
        Self {
            path: PathBuf::from("./data/sled"),
            create_new: true,
            cache_capacity: Some(512 * 1024 * 1024), // 512 MB
            use_compression: false,
            compression_factor: Some(5),
            flush_mode: FlushMode::Auto,
            flush_every_ms: Some(500),
            segment_size: Some(16 * 1024 * 1024), // 16 MB (sled max)
            temporary: false,
            read_only: false,
            print_profile_on_drop: false,
            default_trees: vec![
                // Tree key is the block uuid (UUID v4)
                // Value is the serialized Block structure
                "blocks".to_string(),
                // Tree key is the block height (u64 as bytes)
                // Value is the block uuid (UUID v4)
                "height".to_string(),
            ],
            description: None,
            version: Some("1.0.0".to_string()),
        }
    }
}

impl SledDb {
    /// Create a new SledDb configuration with the given path
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            ..Default::default()
        }
    }
    
    /// Create a configuration for an in-memory temporary database
    pub fn temporary() -> Self {
        Self {
            path: PathBuf::from(format!("/tmp/sled-{}", uuid::Uuid::new_v4())),
            temporary: true,
            ..Default::default()
        }
    }
    
    /// Create a configuration for a read-only database
    pub fn read_only(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            read_only: true,
            create_new: false,
            ..Default::default()
        }
    }
    
    /// Create a high-performance configuration (less durable)
    pub fn high_performance(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            cache_capacity: Some(1024 * 1024 * 1024), // 1 GB cache
            use_compression: false,
            flush_mode: FlushMode::Auto,
            flush_every_ms: Some(5000), // Flush every 5 seconds
            segment_size: Some(16 * 1024 * 1024), // 16 MB (sled max)
            // Struct update syntax: uses default values for all other fields
            // (create_new, compression_factor, temporary, read_only, etc.)
            ..Default::default()
        }
    }
    
    /// Create a high-durability configuration (slower performance)
    pub fn high_durability(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            cache_capacity: Some(256 * 1024 * 1024), // 256 MB cache
            use_compression: true,
            compression_factor: Some(10),
            flush_mode: FlushMode::EveryOp,
            flush_every_ms: None,
            segment_size: Some(8 * 1024 * 1024), // 8 MB segments
            ..Default::default()
        }
    }
    
    /// Open a Sled database with this configuration
    pub fn open(&self) -> std::io::Result<sled::Db> {
        let mut config = sled::Config::new().path(&self.path);
        
        // Apply cache capacity
        if let Some(capacity) = self.cache_capacity {
            config = config.cache_capacity(capacity);
        }
        
        // Apply compression
        if self.use_compression {
            config = config.use_compression(true);
            if let Some(factor) = self.compression_factor {
                config = config.compression_factor(factor);
            }
        }
        
        // Apply flush mode
        match self.flush_mode {
            FlushMode::Auto => {
                if let Some(ms) = self.flush_every_ms {
                    config = config.flush_every_ms(Some(ms));
                }
            }
            FlushMode::EveryOp => {
                config = config.flush_every_ms(Some(0));
            }
            FlushMode::Never => {
                config = config.flush_every_ms(None);
            }
        }
        
        // Apply segment size
        if let Some(size) = self.segment_size {
            config = config.segment_size(size);
        }
        
        // Apply temporary mode
        if self.temporary {
            config = config.temporary(true);
        }
        
        // Apply read-only mode
        if self.read_only {
            config = config.mode(sled::Mode::LowSpace);
        }
        
        // Apply print profile
        if self.print_profile_on_drop {
            config = config.print_profile_on_drop(true);
        }
        
        // Open the database
        let db = config.open()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        
        // Create default trees if specified
        if self.create_new {
            for tree_name in &self.default_trees {
                db.open_tree(tree_name)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            }
        }
        
        Ok(db)
    }
    
    // ===== Builder Pattern Methods =====
    
    /// Set the database path
    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = path.into();
        self
    }
    
    /// Set cache capacity in bytes
    pub fn with_cache_capacity(mut self, bytes: u64) -> Self {
        self.cache_capacity = Some(bytes);
        self
    }
    
    /// Set cache capacity in megabytes
    pub fn with_cache_capacity_mb(mut self, megabytes: u64) -> Self {
        self.cache_capacity = Some(megabytes * 1024 * 1024);
        self
    }
    
    /// Enable compression with optional factor (1-22)
    pub fn with_compression(mut self, factor: Option<i32>) -> Self {
        self.use_compression = true;
        self.compression_factor = factor;
        self
    }
    
    /// Set flush mode
    pub fn with_flush_mode(mut self, mode: FlushMode) -> Self {
        self.flush_mode = mode;
        self
    }
    
    /// Set flush interval in milliseconds
    pub fn with_flush_every_ms(mut self, ms: u64) -> Self {
        self.flush_every_ms = Some(ms);
        self
    }
    
    /// Set segment size in bytes
    pub fn with_segment_size(mut self, bytes: usize) -> Self {
        self.segment_size = Some(bytes);
        self
    }
    
    /// Set segment size in megabytes
    pub fn with_segment_size_mb(mut self, megabytes: usize) -> Self {
        self.segment_size = Some(megabytes * 1024 * 1024);
        self
    }
    
    /// Add a default tree to create on initialization
    pub fn with_tree(mut self, tree_name: impl Into<String>) -> Self {
        self.default_trees.push(tree_name.into());
        self
    }
    
    /// Set all default trees
    pub fn with_trees(mut self, trees: Vec<String>) -> Self {
        self.default_trees = trees;
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
    
    /// Enable temporary mode (deleted on close)
    pub fn as_temporary(mut self) -> Self {
        self.temporary = true;
        self
    }
    
    /// Enable read-only mode
    pub fn as_read_only(mut self) -> Self {
        self.read_only = true;
        self.create_new = false;
        self
    }
    
    /// Enable profile printing on drop (for debugging)
    pub fn with_profile_on_drop(mut self) -> Self {
        self.print_profile_on_drop = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SledDb::default();
        assert_eq!(config.path, PathBuf::from("./data/sled"));
        assert_eq!(config.create_new, true);
        assert_eq!(config.cache_capacity, Some(512 * 1024 * 1024));
        assert_eq!(config.flush_mode, FlushMode::Auto);
    }

    #[test]
    fn test_builder_pattern() {
        let config = SledDb::new("/tmp/test")
            .with_cache_capacity_mb(256)
            .with_compression(Some(10))
            .with_flush_mode(FlushMode::EveryOp)
            .with_tree("custom_tree")
            .with_description("Test database");
        
        assert_eq!(config.path, PathBuf::from("/tmp/test"));
        assert_eq!(config.cache_capacity, Some(256 * 1024 * 1024));
        assert_eq!(config.use_compression, true);
        assert_eq!(config.compression_factor, Some(10));
        assert_eq!(config.flush_mode, FlushMode::EveryOp);
        assert!(config.default_trees.contains(&"custom_tree".to_string()));
    }

    #[test]
    fn test_presets() {
        let temp = SledDb::temporary();
        assert_eq!(temp.temporary, true);
        
        let readonly = SledDb::read_only("/tmp/readonly");
        assert_eq!(readonly.read_only, true);
        assert_eq!(readonly.create_new, false);
        
        let perf = SledDb::high_performance("/tmp/perf");
        assert_eq!(perf.cache_capacity, Some(1024 * 1024 * 1024));
        assert_eq!(perf.flush_mode, FlushMode::Auto);
        
        let durable = SledDb::high_durability("/tmp/durable");
        assert_eq!(durable.flush_mode, FlushMode::EveryOp);
        assert_eq!(durable.use_compression, true);
    }
}
