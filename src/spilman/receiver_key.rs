//! The payee's **receiver key** — persisted, stable, and never sent anywhere.
//!
//! # Why this is a file and not a per-boot value
//!
//! The receiver key is the key a channel is *addressed to*: the payer names its public
//! half in `params_json`, and the payee signs the close with the secret half. If the
//! secret were regenerated at boot — or if the payer generated its own, which is what
//! `examples/spilman_payer.rs` used to do — then:
//!
//! - a channel opened before a restart could never be settled afterwards, because the
//!   payee no longer holds the key it is addressed to; and
//! - a channel opened against the wrong key could never be settled at all, which is the
//!   HTTP 409 measured at `POST /spilman/close` on real hardware.
//!
//! So the secret lives on disk, created once, mode `0600`, hex-encoded, and reloaded on
//! every boot. [`crate::spilman::SpilmanRail::receiver_pubkey`] is what `/spilman/params`
//! advertises, and it is derived from exactly this file.
//!
//! # Why not reuse the merchant (Nostr) identity
//!
//! `main.rs` used to derive the receiver key from `identities.json`. That works, but
//! `/spilman/params` is a *public* endpoint, and a compressed secp256k1 key shares its
//! x-coordinate with the merchant's x-only Nostr pubkey — so advertising it would link
//! the router's Nostr identity to its payment rail for anyone who can read the endpoint.
//! A dedicated key keeps the two identities unlinkable, at the cost of one more file to
//! keep.

use std::path::{Path, PathBuf};

use cashu::nuts::SecretKey;

use crate::spilman::SpilmanError;

/// File name this module uses inside the config directory.
pub const RECEIVER_KEY_FILE: &str = "spilman-receiver.key";

/// The default location: `<config dir>/spilman-receiver.key`.
///
/// Resolved through [`crate::config::config_dir`], so `TOLLGATE_TEST_CONFIG_DIR` moves it
/// in tests and `/etc/tollgate` is the production path — the same rule every other
/// file this module reads follows.
pub fn default_path() -> PathBuf {
    crate::config::config_dir().join(RECEIVER_KEY_FILE)
}

/// Load the receiver key at `path`, creating it if it does not exist.
///
/// # Failure modes, all refusals
///
/// - the file exists but is not 32 bytes of hex → `Err` (never "generate a new one":
///   that would silently orphan every open channel);
/// - the file exists but is not a valid secp256k1 scalar → `Err`;
/// - the file cannot be read or written → `Err`.
///
/// A creation race (two processes booting at once) is resolved in favour of the file
/// that won: the key is created with `create_new`, so the loser re-reads the winner's
/// file rather than overwriting it.
pub fn load_or_create(path: &Path) -> Result<SecretKey, SpilmanError> {
    match load(path)? {
        Some(key) => Ok(key),
        None => create(path),
    }
}

/// Read `path` if it exists. `Ok(None)` means "not there yet", which is the only state
/// that permits generation.
fn load(path: &Path) -> Result<Option<SecretKey>, SpilmanError> {
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(SpilmanError::Io {
                path: path.display().to_string(),
                detail: e.to_string(),
            })
        }
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(SpilmanError::Io {
            path: path.display().to_string(),
            detail: "the receiver key file is empty; refusing to generate a replacement \
                     (open channels would become uncloseable)"
                .to_string(),
        });
    }
    let bytes = hex::decode(trimmed).map_err(|e| SpilmanError::Io {
        path: path.display().to_string(),
        detail: format!("not hex: {e}"),
    })?;
    SecretKey::from_slice(&bytes)
        .map(Some)
        .map_err(|e| SpilmanError::Io {
            path: path.display().to_string(),
            detail: format!("not a secp256k1 secret key: {e}"),
        })
}

/// Generate and persist a new key with `0600`, then return it.
fn create(path: &Path) -> Result<SecretKey, SpilmanError> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| SpilmanError::Io {
            path: parent.display().to_string(),
            detail: e.to_string(),
        })?;
    }

    let key = SecretKey::generate();
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // 0600 from the moment the file exists: a window where the secret is readable by
        // others is exactly the window worth attacking.
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => {
            file.write_all(format!("{}\n", hex::encode(key.secret_bytes())).as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|e| SpilmanError::Io {
                    path: path.display().to_string(),
                    detail: e.to_string(),
                })?;
            Ok(key)
        }
        // Two boots raced; the other process won. Read ITS key rather than overwriting,
        // because it may already be advertised.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            load(path)?.ok_or_else(|| SpilmanError::Io {
                path: path.display().to_string(),
                detail: "the receiver key vanished between create and read".to_string(),
            })
        }
        Err(e) => Err(SpilmanError::Io {
            path: path.display().to_string(),
            detail: e.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_key_is_persisted_with_owner_only_permissions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(RECEIVER_KEY_FILE);
        assert!(!path.exists());

        let key = load_or_create(&path).expect("create");
        assert!(path.exists(), "the key must be written to disk");

        let raw = std::fs::read_to_string(&path).expect("read");
        assert_eq!(raw.trim(), hex::encode(key.secret_bytes()));
        assert_eq!(raw.trim().len(), 64, "hex-encoded 32 bytes");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "the receiver key must not be readable by anyone else (got {mode:o})"
            );
        }
    }

    /// **The restart property.** A per-boot key would silently break every channel.
    #[test]
    fn the_same_key_is_reloaded_after_a_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(RECEIVER_KEY_FILE);

        let first = load_or_create(&path).expect("first boot");
        let second = load_or_create(&path).expect("second boot");
        assert_eq!(
            first.secret_bytes(),
            second.secret_bytes(),
            "a restart must reload the persisted key, not generate a new one"
        );
        assert_eq!(first.public_key(), second.public_key());
    }

    /// A corrupt file is a refusal, never a quiet replacement: replacing it would orphan
    /// every channel already opened against the old key.
    #[test]
    fn a_corrupt_file_is_refused_and_left_untouched() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(RECEIVER_KEY_FILE);

        for bad in ["", "   \n", "zz", "0011", &"00".repeat(32)] {
            std::fs::write(&path, bad).expect("write");
            let err = load_or_create(&path).expect_err("must refuse");
            let message = err.to_string();
            assert!(
                message.contains(RECEIVER_KEY_FILE),
                "the refusal must name the file it could not use: {message}"
            );
            assert_eq!(
                std::fs::read_to_string(&path).expect("read"),
                bad,
                "a refused load must not rewrite the file"
            );
        }
    }

    /// The file is the only source: two different paths are two different keys.
    #[test]
    fn each_path_holds_its_own_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let a = load_or_create(&dir.path().join("a.key")).expect("a");
        let b = load_or_create(&dir.path().join("b.key")).expect("b");
        assert_ne!(a.public_key(), b.public_key());
    }
}
