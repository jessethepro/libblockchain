use anyhow::{Result, anyhow};
use libblockchain::blockchain::open_chain;
use std::thread;

#[test]
fn shared_chain_handle_can_be_used_across_threads() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let db_path = temp_dir.path().join("chain");
    let db_path = db_path.to_string_lossy().into_owned();

    let chain = open_chain(&db_path)?;
    chain.put_block(b"genesis".to_vec(), b"sig0".to_vec())?;

    let writer = chain.clone();
    let joined_height = thread::spawn(move || writer.put_block(b"next".to_vec(), b"sig1".to_vec()))
        .join()
        .map_err(|_| anyhow!("writer thread panicked"))??;

    assert_eq!(joined_height, 1);
    assert_eq!(chain.block_count()?, 2);

    let (block, signature) = chain.get_block_by_height(1);
    assert_eq!(block?.block_data(), b"next".to_vec());
    assert_eq!(signature?, b"sig1".to_vec());

    Ok(())
}
