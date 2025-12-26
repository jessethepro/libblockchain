use anyhow::{Result, anyhow};
use keyutils::keytypes::user::User;
use keyutils::{Keyring, SpecialKeyring};

fn main() -> Result<()> {
    // Attach to the process keyring
    let keyring = Keyring::attach(SpecialKeyring::Process)
        .map_err(|e| anyhow!("Failed to attach to process keyring: {}", e))?;

    // Search for a key by name (description)
    let key_name = "pki-chain-app.private_key";
    let key = keyring
        .search_for_key::<User, _, _>(key_name, None)
        .map_err(|e| anyhow!("Failed to find key '{}': {}", key_name, e))?;

    // Read the key's data
    let key_data = key
        .read()
        .map_err(|e| anyhow!("Failed to read key data: {}", e))?;

    println!("Successfully read key '{}'", key_name);
    println!("Key data length: {} bytes", key_data.len());

    // Optionally display first few bytes (be careful with sensitive data!)
    if key_data.len() > 0 {
        println!(
            "First 16 bytes (hex): {:02x?}",
            &key_data[..key_data.len().min(16)]
        );
    }

    Ok(())
}
