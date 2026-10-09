use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    process,
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{Context, anyhow};
use discv5::{Enr, enr::CombinedKey};
use tracing::warn;

const MAX_TEMP_FILE_ATTEMPTS: usize = 64;

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Reads the saved local ENR. Returns `Ok(None)` if no ENR has been saved yet.
pub fn load_enr(path: &Path) -> anyhow::Result<Option<Enr>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("Failed to read saved ENR {}", path.display()));
        }
    };

    let enr = Enr::from_str(contents.trim()).map_err(|err| {
        anyhow!(
            "Saved ENR {} is malformed ({err}); delete it to start a new ENR sequence",
            path.display()
        )
    })?;
    Ok(Some(enr))
}

/// Returns the IP for the local ENR. With an unspecified listen address, the IP learned from peers
/// in a previous run is reused so a restart doesn't drop it or change the record.
pub fn advertised_ip(configured: IpAddr, previous: Option<&Enr>) -> IpAddr {
    if !configured.is_unspecified() {
        return configured;
    }
    let learned = match configured {
        IpAddr::V4(_) => previous.and_then(Enr::ip4).map(IpAddr::V4),
        IpAddr::V6(_) => previous.and_then(Enr::ip6).map(IpAddr::V6),
    };
    learned
        .filter(|ip| !ip.is_unspecified())
        .unwrap_or(configured)
}

/// Continues the sequence of `previous` in a freshly built `enr` for the same node.
///
/// Peers only replace a stored ENR when the new sequence number is higher, so a changed record
/// must use a higher number than any record published before (EIP-778).
pub fn continue_enr_seq(enr: &mut Enr, previous: &Enr, key: &CombinedKey) -> anyhow::Result<()> {
    if previous.node_id() != enr.node_id() {
        return Ok(());
    }

    if previous.iter().eq(enr.iter()) {
        *enr = previous.clone();
        return Ok(());
    }

    let seq = previous
        .seq()
        .checked_add(1)
        .ok_or_else(|| anyhow!("ENR sequence number overflow"))?;
    enr.set_seq(seq.max(enr.seq()), key)
        .map_err(|err| anyhow!("Failed to set ENR sequence number: {err:?}"))
}

/// Replaces the saved ENR with `enr`. The new record is written to a temp file and renamed into
/// place, so a crash never leaves a partial ENR behind.
pub fn save_enr(path: &Path, enr: &Enr) -> anyhow::Result<()> {
    let context = || format!("Failed to save ENR to {}", path.display());
    let (temp_path, mut temp_file) = create_temp_file(path).with_context(context)?;

    let result = temp_file
        .write_all(enr.to_base64().as_bytes())
        .and_then(|()| temp_file.sync_all())
        .and_then(|()| fs::rename(&temp_path, path));
    drop(temp_file);

    if result.is_err()
        && let Err(err) = fs::remove_file(&temp_path)
    {
        warn!(
            "Failed to remove temporary ENR {}: {err}",
            temp_path.display()
        );
    }
    result.with_context(context)?;

    sync_parent_dir(path).with_context(context)
}

/// Creates a temp file next to `path` that belongs to this call only.
fn create_temp_file(path: &Path) -> io::Result<(PathBuf, File)> {
    let file_name = path.file_name().unwrap_or_default().to_string_lossy();
    for _ in 0..MAX_TEMP_FILE_ATTEMPTS {
        let temp_path = path.with_file_name(format!(
            "{file_name}.tmp.{}.{}",
            process::id(),
            TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
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

#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> io::Result<()> {
    match path.parent() {
        Some(parent) => File::open(parent)?.sync_all(),
        None => Ok(()),
    }
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
pub(crate) mod test_utils {
    use std::{
        env, fs,
        path::{Path, PathBuf},
        process,
        sync::atomic::{AtomicU64, Ordering},
    };

    pub(crate) struct TestDir(PathBuf);

    impl TestDir {
        pub(crate) fn new() -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let path = env::temp_dir().join(format!(
                "ream_discv5_test_{}_{}",
                process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        pub(crate) fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use discv5::enr::k256::ecdsa::SigningKey;

    use super::{test_utils::TestDir, *};

    fn key() -> CombinedKey {
        CombinedKey::Secp256k1(SigningKey::random(&mut rand::thread_rng()))
    }

    fn enr(key: &CombinedKey, tcp_port: u16) -> Enr {
        Enr::builder().tcp4(tcp_port).build(key).unwrap()
    }

    #[test]
    fn advertised_ip_reuses_learned_ip_only_for_unspecified_address() {
        let key = key();
        let learned: IpAddr = "203.0.113.7".parse().unwrap();
        let previous = Enr::builder().ip(learned).build(&key).unwrap();
        let unspecified: IpAddr = "0.0.0.0".parse().unwrap();
        let configured: IpAddr = "198.51.100.1".parse().unwrap();

        assert_eq!(advertised_ip(unspecified, Some(&previous)), learned);
        assert_eq!(advertised_ip(configured, Some(&previous)), configured);
        assert_eq!(advertised_ip(unspecified, None), unspecified);

        let never_learned = Enr::builder().ip(unspecified).build(&key).unwrap();
        assert_eq!(
            advertised_ip(unspecified, Some(&never_learned)),
            unspecified
        );

        let ipv6_unspecified: IpAddr = "::".parse().unwrap();
        assert_eq!(
            advertised_ip(ipv6_unspecified, Some(&previous)),
            ipv6_unspecified
        );
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = TestDir::new();
        let path = dir.path().join("enr");
        assert!(load_enr(&path).unwrap().is_none());

        let enr = enr(&key(), 9000);
        save_enr(&path, &enr).unwrap();

        assert_eq!(load_enr(&path).unwrap(), Some(enr));
        let entries: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec!["enr"]);
    }

    #[test]
    fn malformed_saved_enr_is_an_error() {
        let dir = TestDir::new();
        let path = dir.path().join("enr");
        fs::write(&path, "enr:not-a-record").unwrap();

        assert!(load_enr(&path).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "enr:not-a-record");
    }

    #[test]
    fn unchanged_record_keeps_previous_seq() {
        let key = key();
        let mut previous = enr(&key, 9000);
        previous.set_seq(7, &key).unwrap();

        let mut rebuilt = enr(&key, 9000);
        continue_enr_seq(&mut rebuilt, &previous, &key).unwrap();

        assert_eq!(rebuilt, previous);
    }

    #[test]
    fn changed_record_increments_previous_seq() {
        let key = key();
        let mut previous = enr(&key, 9000);
        previous.set_seq(7, &key).unwrap();

        let mut rebuilt = enr(&key, 9001);
        continue_enr_seq(&mut rebuilt, &previous, &key).unwrap();

        assert_eq!(rebuilt.seq(), 8);
        assert_eq!(rebuilt.tcp4(), Some(9001));
        assert!(rebuilt.verify());
    }

    #[test]
    fn record_of_another_node_is_ignored() {
        let other_key = key();
        let mut previous = enr(&other_key, 9000);
        previous.set_seq(7, &other_key).unwrap();

        let key = key();
        let mut rebuilt = enr(&key, 9001);
        continue_enr_seq(&mut rebuilt, &previous, &key).unwrap();

        assert_eq!(rebuilt.seq(), 1);
    }
}
