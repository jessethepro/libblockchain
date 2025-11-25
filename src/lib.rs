pub mod block;
pub mod traits;

pub use block::{Block, BlockHeader, BLOCK_VERSION};
pub use traits::{BlockHeaderHasher, GenesisBlock, RegularBlock};

// Re-export uuid for convenience
pub use uuid;
