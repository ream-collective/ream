use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
};

use alloy_primitives::hex;
use anyhow::{Context, anyhow};
use libp2p_identity::secp256k1;
use tracing::{info, warn};

/// Hex secp256k1 secret key shared by discv5 (NodeId) and libp2p (PeerId).
pub const NETWORK_KEY_FILE_NAME: &str = "beacon_network_key";

/// Last published local ENR, so its sequence number keeps increasing across restarts.
pub const ENR_FILE_NAME: &str = "beacon_enr";

const MAX_TEMP_FILE_ATTEMPTS: usize = 64;

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Loads the beacon network key, creating it only if the key file is missing.
///
/// A key file that can't be read or decoded is an error and is never replaced.
pub fn load_or_create_network_key(data_dir: &Path) -> anyhow::Result<secp256k1::Keypair> {
    let key_path = data_dir.join(NETWORK_KEY_FILE_NAME);

    if let Some(keypair) = read_network_key(&key_path)? {
        info!("Loaded beacon network key from {}", key_path.display());
        return Ok(keypair);
    }

    fs::create_dir_all(data_dir).with_context(|| {
        format!(
            "Failed to create beacon network data directory {}",
            data_dir.display()
        )
    })?;

    let keypair = secp256k1::Keypair::generate();
    if persist_new_network_key(&key_path, &keypair)? {
        info!("Generated new beacon network key at {}", key_path.display());
        return Ok(keypair);
    }

    // Another process created the key first; use it.
    read_network_key(&key_path)?.ok_or_else(|| {
        anyhow!(
            "Beacon network key {} exists but could not be opened",
            key_path.display()
        )
    })
}

/// Returns `Ok(None)` only when the key file does not exist.
fn read_network_key(key_path: &Path) -> anyhow::Result<Option<secp256k1::Keypair>> {
    let contents = match fs::read_to_string(key_path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| {
                format!("Failed to read beacon network key {}", key_path.display())
            });
        }
    };

    warn_if_permissive(key_path);

    // Drop decode errors so no part of the key reaches the logs.
    let secret_key_bytes = hex::decode(contents.trim()).ok().with_context(|| {
        format!(
            "Beacon network key {} is not valid hex; refusing to replace it",
            key_path.display()
        )
    })?;
    let secret_key = secp256k1::SecretKey::try_from_bytes(secret_key_bytes)
        .ok()
        .with_context(|| {
            format!(
                "Beacon network key {} is not a valid secp256k1 secret key; refusing to replace it",
                key_path.display()
            )
        })?;

    Ok(Some(secp256k1::Keypair::from(secret_key)))
}

/// Writes the key to a private temp file, then hard links it into place so an existing key is
/// never overwritten. Returns `Ok(false)` if a key already exists.
fn persist_new_network_key(key_path: &Path, keypair: &secp256k1::Keypair) -> anyhow::Result<bool> {
    let context = || {
        format!(
            "Failed to persist beacon network key {}",
            key_path.display()
        )
    };
    let (temp_path, mut temp_file) = create_temp_key_file(key_path).with_context(context)?;

    let result = temp_file
        .write_all(hex::encode(keypair.secret().to_bytes()).as_bytes())
        .and_then(|()| temp_file.sync_all())
        .and_then(|()| match fs::hard_link(&temp_path, key_path) {
            Ok(()) => Ok(true),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            Err(err) => Err(err),
        });
    drop(temp_file);

    if let Err(err) = fs::remove_file(&temp_path) {
        warn!(
            "Failed to remove temporary beacon network key {}: {err}",
            temp_path.display()
        );
    }

    let created = result.with_context(context)?;
    if created {
        sync_parent_dir(key_path)?;
    }
    Ok(created)
}

/// Creates an owner-only temp file that belongs to this call, so cleanup never removes a file
/// created by a concurrent caller.
fn create_temp_key_file(key_path: &Path) -> io::Result<(PathBuf, File)> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    for _ in 0..MAX_TEMP_FILE_ATTEMPTS {
        let temp_path = temp_key_path(key_path, TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed));
        match options.open(&temp_path) {
            Ok(file) => return Ok((temp_path, file)),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "no unused temporary file name",
    ))
}

fn temp_key_path(key_path: &Path, id: u64) -> PathBuf {
    let mut file_name = key_path.file_name().unwrap_or_default().to_os_string();
    file_name.push(format!(".tmp.{}.{id}", process::id()));
    key_path.with_file_name(file_name)
}

#[cfg(unix)]
fn sync_parent_dir(key_path: &Path) -> anyhow::Result<()> {
    let Some(parent) = key_path.parent() else {
        return Ok(());
    };
    File::open(parent)
        .and_then(|dir| dir.sync_all())
        .with_context(|| format!("Failed to sync directory {}", parent.display()))
}

#[cfg(not(unix))]
fn sync_parent_dir(_key_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn warn_if_permissive(key_path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    if let Ok(metadata) = fs::metadata(key_path) {
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            warn!(
                "Beacon network key {} is accessible by other users (mode {mode:o}); consider \
                 restricting it to 600",
                key_path.display()
            );
        }
    }
}

#[cfg(not(unix))]
fn warn_if_permissive(_key_path: &Path) {}

#[cfg(test)]
pub(crate) mod test_utils {
    use std::{
        env, fs,
        path::{Path, PathBuf},
        process,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    pub(crate) struct TestDataDir(PathBuf);

    impl TestDataDir {
        pub(crate) fn new() -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = env::temp_dir().join(format!(
                "ream_beacon_network_test_{}_{nanos}_{}",
                process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        pub(crate) fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDataDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Barrier, thread};

    use libp2p_identity::{Keypair, PeerId};

    use super::{test_utils::TestDataDir, *};

    fn peer_id(keypair: &secp256k1::Keypair) -> PeerId {
        PeerId::from_public_key(&Keypair::from(keypair.clone()).public())
    }

    #[test]
    fn creates_key_when_absent_and_reloads_it() {
        let data_dir = TestDataDir::new();
        let key_path = data_dir.path().join(NETWORK_KEY_FILE_NAME);
        assert!(!key_path.exists());

        let created = load_or_create_network_key(data_dir.path()).unwrap();
        assert!(key_path.exists());
        let contents = fs::read(&key_path).unwrap();

        let reloaded = load_or_create_network_key(data_dir.path()).unwrap();
        assert_eq!(created.secret().to_bytes(), reloaded.secret().to_bytes());
        assert_eq!(peer_id(&created), peer_id(&reloaded));
        assert_eq!(fs::read(&key_path).unwrap(), contents);

        let entries: Vec<_> = fs::read_dir(data_dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![NETWORK_KEY_FILE_NAME]);
    }

    #[test]
    fn creates_missing_data_directory() {
        let data_dir = TestDataDir::new();
        let nested = data_dir.path().join("nested");

        load_or_create_network_key(&nested).unwrap();

        assert!(nested.join(NETWORK_KEY_FILE_NAME).is_file());
    }

    #[test]
    fn independent_data_directories_have_independent_keys() {
        let data_dir_1 = TestDataDir::new();
        let data_dir_2 = TestDataDir::new();

        let key_1 = load_or_create_network_key(data_dir_1.path()).unwrap();
        let key_2 = load_or_create_network_key(data_dir_2.path()).unwrap();

        assert_ne!(peer_id(&key_1), peer_id(&key_2));
    }

    #[test]
    fn loads_existing_hex_key() {
        let data_dir = TestDataDir::new();
        let keypair = secp256k1::Keypair::generate();
        // `ream generate_private_key` format, with a trailing newline.
        fs::write(
            data_dir.path().join(NETWORK_KEY_FILE_NAME),
            format!("{}\n", hex::encode(keypair.secret().to_bytes())),
        )
        .unwrap();

        let loaded = load_or_create_network_key(data_dir.path()).unwrap();

        assert_eq!(peer_id(&loaded), peer_id(&keypair));
    }

    #[test]
    fn malformed_key_is_rejected_and_not_replaced() {
        for malformed in [
            b"not a hex key".to_vec(),
            b"".to_vec(),
            b"abcd".to_vec(),
            // Zero is not a valid secp256k1 scalar.
            hex::encode([0u8; 32]).into_bytes(),
            vec![0xff, 0xfe, 0x00],
        ] {
            let data_dir = TestDataDir::new();
            let key_path = data_dir.path().join(NETWORK_KEY_FILE_NAME);
            fs::write(&key_path, &malformed).unwrap();

            let err = load_or_create_network_key(data_dir.path()).unwrap_err();

            assert!(
                err.to_string().contains(NETWORK_KEY_FILE_NAME),
                "unexpected error: {err:#}"
            );
            assert_eq!(fs::read(&key_path).unwrap(), malformed);
        }
    }

    #[test]
    fn unreadable_key_path_is_rejected() {
        let data_dir = TestDataDir::new();
        let key_path = data_dir.path().join(NETWORK_KEY_FILE_NAME);
        fs::create_dir(&key_path).unwrap();

        assert!(load_or_create_network_key(data_dir.path()).is_err());
        assert!(key_path.is_dir());
    }

    #[test]
    fn persist_does_not_overwrite_existing_key() {
        let data_dir = TestDataDir::new();
        let key_path = data_dir.path().join(NETWORK_KEY_FILE_NAME);
        let existing = load_or_create_network_key(data_dir.path()).unwrap();
        let contents = fs::read(&key_path).unwrap();

        let created = persist_new_network_key(&key_path, &secp256k1::Keypair::generate()).unwrap();

        assert!(!created);
        assert_eq!(fs::read(&key_path).unwrap(), contents);
        assert_eq!(
            peer_id(&load_or_create_network_key(data_dir.path()).unwrap()),
            peer_id(&existing)
        );
    }

    #[test]
    fn concurrent_creators_share_one_key() {
        let data_dir = TestDataDir::new();
        let barrier = Barrier::new(16);

        let peer_ids: Vec<_> = thread::scope(|scope| {
            let handles: Vec<_> = (0..16)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        peer_id(&load_or_create_network_key(data_dir.path()).unwrap())
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect()
        });

        assert!(peer_ids.iter().all(|peer_id| *peer_id == peer_ids[0]));
        let entries: Vec<_> = fs::read_dir(data_dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![NETWORK_KEY_FILE_NAME]);
    }

    #[test]
    fn temp_files_of_other_creators_are_left_untouched() {
        let data_dir = TestDataDir::new();
        let key_path = data_dir.path().join(NETWORK_KEY_FILE_NAME);
        let next_id = TEMP_FILE_COUNTER.load(Ordering::Relaxed);
        let foreign_paths: Vec<_> = (next_id..next_id + 32)
            .map(|id| temp_key_path(&key_path, id))
            .collect();
        for path in &foreign_paths {
            fs::write(path, "foreign").unwrap();
        }

        load_or_create_network_key(data_dir.path()).unwrap();

        for path in &foreign_paths {
            assert_eq!(fs::read_to_string(path).unwrap(), "foreign");
        }
    }

    #[cfg(unix)]
    #[test]
    fn new_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let data_dir = TestDataDir::new();
        load_or_create_network_key(data_dir.path()).unwrap();

        let mode = fs::metadata(data_dir.path().join(NETWORK_KEY_FILE_NAME))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
