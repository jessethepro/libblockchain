#![warn(clippy::unwrap_used)]
#![warn(clippy::indexing_slicing)]

pub mod block;
pub mod blockchain;
pub mod db_model;

// Re-export uuid for convenience
pub use uuid;
