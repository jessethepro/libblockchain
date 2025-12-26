# Reading Keys from Linux Keyring using keyutils

## Overview
The `keyutils` crate provides Rust bindings to the Linux kernel's keyring subsystem. This allows secure storage and retrieval of cryptographic keys, passwords, and other sensitive data.

## Basic API Pattern

### 1. Attach to a Keyring

```rust
use keyutils::{Keyring, SpecialKeyring};

// Attach to the process keyring
let keyring = Keyring::attach(SpecialKeyring::Process)?;

// Or attach to other keyrings:
// - SpecialKeyring::Thread   - Thread-specific keyring
// - SpecialKeyring::Session  - Session-specific keyring
// - SpecialKeyring::User     - User-specific keyring
```

### 2. Search for a Key by Name

```rust
use keyutils::keytypes::user::User;

// Search for a key with a specific description (name)
let key = keyring.search_for_key::<User, _, _>("my-key-name", None)?;

// The User type indicates this is a "user" type key (most common)
// Other key types: asymmetric, logon, big_key, encrypted, trusted
```

### 3. Read the Key Data

```rust
// Read returns Vec<u8>
let key_data: Vec<u8> = key.read()?;

// For DER-encoded keys, use directly with OpenSSL
use openssl::pkey::PKey;
let private_key = PKey::private_key_from_der(&key_data)?;
```

## Complete Example

```rust
use anyhow::{Result, anyhow};
use keyutils::{Keyring, SpecialKeyring};
use keyutils::keytypes::user::User;
use openssl::pkey::PKey;

fn read_private_key_from_keyring(key_name: &str) -> Result<PKey<openssl::pkey::Private>> {
    // 1. Attach to process keyring
    let keyring = Keyring::attach(SpecialKeyring::Process)
        .map_err(|e| anyhow!("Failed to attach to process keyring: {}", e))?;

    // 2. Search for the key
    let key = keyring
        .search_for_key::<User, _, _>(key_name, None)
        .map_err(|e| anyhow!("Key '{}' not found in keyring: {}", key_name, e))?;

    // 3. Read the key data
    let key_der = key.read()
        .map_err(|e| anyhow!("Failed to read key: {}", e))?;

    // 4. Parse as OpenSSL private key
    let private_key = PKey::private_key_from_der(&key_der)
        .map_err(|e| anyhow!("Failed to parse key DER: {}", e))?;

    Ok(private_key)
}
```

## Adding Keys to the Keyring

### From Command Line
```bash
# Add a key from a file
keyctl padd user my-key-name @p < /path/to/key.der

# Add a key from stdin
echo -n "my-secret-data" | keyctl padd user my-key-name @p

# List keys in process keyring
keyctl show @p
```

### From Rust Code
```rust
use keyutils::keytypes::user::User;

// Add or update a key
let mut keyring = Keyring::attach(SpecialKeyring::Process)?;
let key_data = std::fs::read("/path/to/key.der")?;
let key = keyring.add_key::<User, _, _>("my-key-name", &key_data)?;
```

## Key Types

- **user**: General-purpose keys (most common)
- **asymmetric**: Public/private key pairs
- **logon**: Login credentials (cannot be read by userspace)
- **big_key**: Large keys stored in tmpfs
- **encrypted**: Keys encrypted with master key
- **trusted**: Keys sealed by TPM

## Common Patterns

### Check if Key Exists
```rust
match keyring.search_for_key::<User, _, _>("my-key", None) {
    Ok(key) => println!("Key found"),
    Err(_) => println!("Key not found"),
}
```

### Read Key with Fallback
```rust
fn get_key_or_load_from_file(name: &str, path: &str) -> Result<Vec<u8>> {
    let keyring = Keyring::attach(SpecialKeyring::Process)?;
    
    match keyring.search_for_key::<User, _, _>(name, None) {
        Ok(key) => key.read().map_err(Into::into),
        Err(_) => {
            // Key not in keyring, load from file
            let data = std::fs::read(path)?;
            // Optionally add to keyring for next time
            let mut keyring = keyring;
            keyring.add_key::<User, _, _>(name, &data)?;
            Ok(data)
        }
    }
}
```

### Update Key Permissions
```rust
use keyutils::Permission;

let mut key = keyring.search_for_key::<User, _, _>("my-key", None)?;

// Set permissions (rwx for possessor, r for user, no access for others)
let perms = Permission::POSSESSOR_ALL | Permission::USER_READ;
key.set_permissions(perms)?;
```

## Security Considerations

1. **Access Control**: Keys are protected by Linux kernel permissions
2. **Process Isolation**: Process keyrings are isolated between processes
3. **Persistence**: Keys can be persistent or session-based
4. **No Logging**: Key data is never written to logs by the kernel
5. **Memory Protection**: Keys stored in kernel memory, not swappable

## Error Handling

Common errors:
- **ENOKEY**: Key not found
- **EACCES**: Permission denied
- **EKEYREVOKED**: Key has been revoked
- **EKEYEXPIRED**: Key has expired

```rust
use keyutils::Error;

match keyring.search_for_key::<User, _, _>("my-key", None) {
    Err(Error::NoKey) => eprintln!("Key not found"),
    Err(Error::PermissionDenied) => eprintln!("Access denied"),
    Err(e) => eprintln!("Other error: {:?}", e),
    Ok(key) => { /* use key */ }
}
```

## References

- [keyutils Documentation](https://docs.rs/keyutils/)
- [Linux keyutils man page](https://man7.org/linux/man-pages/man7/keyutils.7.html)
- [kernel keyring documentation](https://www.kernel.org/doc/html/latest/security/keys/core.html)
