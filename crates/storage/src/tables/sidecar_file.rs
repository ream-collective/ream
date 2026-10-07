//! Durable sidecar publication. Writers run on blocking workers, outside fork choice locks.
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    sync::{LazyLock, Mutex},
};

use crate::errors::StoreError;
const TEMP_PREFIX: &str = ".ream-sidecar-";
// Only writers serialize. No filesystem I/O runs under the reader visibility lock.
// true denotes a rollback failure: readers report an error until a writer repairs it.
static WRITER: Mutex<()> = Mutex::new(());
static PENDING: LazyLock<Mutex<HashMap<PathBuf, bool>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn is_pending(path: &Path) -> Result<bool, StoreError> {
    match PENDING
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .get(path)
    {
        Some(true) => Err(std::io::Error::other(
            "Sidecar publication rollback failed; storage repair or retry required",
        )
        .into()),
        Some(false) => Ok(true),
        None => Ok(false),
    }
}

pub(crate) fn open_published(path: &Path) -> Result<Option<File>, StoreError> {
    if is_pending(path)? {
        return Ok(None);
    }
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    // Publication might have started between the first check and open. Files are
    // never modified in place, so a handle that passes both checks stays valid.
    if is_pending(path)? {
        return Ok(None);
    }
    Ok(Some(file))
}

pub struct PreparedSidecarFile {
    file: tempfile::NamedTempFile,
    destination: PathBuf,
}
impl PreparedSidecarFile {
    pub fn new(destination: PathBuf, bytes: &[u8]) -> Result<Self, StoreError> {
        let parent = destination
            .parent()
            .ok_or_else(|| std::io::Error::other("Sidecar path has no parent"))?;
        let mut file = tempfile::Builder::new()
            .prefix(TEMP_PREFIX)
            .tempfile_in(parent)?;
        file.write_all(bytes)?;
        file.as_file().sync_all()?;
        Ok(Self { file, destination })
    }
    pub fn publish(self) -> Result<(), StoreError> {
        Self::publish_batch(vec![self])
    }

    /// Run the entire publication in one blocking task: cancellation cannot interrupt it.
    /// Byte-identical duplicates remain readable; different bytes are atomically replaced.
    pub fn publish_batch(files: Vec<Self>) -> Result<(), StoreError> {
        let _writer = WRITER.lock().unwrap_or_else(|err| err.into_inner());
        let mut publication = Publication::default();
        let mut directories = HashSet::new();
        for prepared in files {
            let failed = PENDING
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .get(&prepared.destination)
                .copied()
                == Some(true);
            if failed {
                match fs::remove_file(&prepared.destination) {
                    Ok(()) => {}
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    Err(err) => return Err(err.into()),
                }
                PENDING
                    .lock()
                    .unwrap_or_else(|err| err.into_inner())
                    .remove(&prepared.destination);
            }
            let replace = match fs::read(&prepared.destination) {
                Ok(existing) => {
                    if existing == fs::read(prepared.file.path())? {
                        continue;
                    }
                    true
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
                Err(err) => return Err(err.into()),
            };
            let parent = prepared
                .destination
                .parent()
                .ok_or_else(|| std::io::Error::other("Sidecar path has no parent"))?
                .to_path_buf();
            if replace {
                // Preserve the old inode so a later batch failure cannot destroy a
                // previously readable sidecar (including a different valid encoding).
                let backup = tempfile::Builder::new()
                    .prefix(TEMP_PREFIX)
                    .tempfile_in(&parent)?;
                fs::remove_file(backup.path())?;
                fs::hard_link(&prepared.destination, backup.path())?;
                publication
                    .backups
                    .insert(prepared.destination.clone(), backup);
            }
            PENDING
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .insert(prepared.destination.clone(), false);
            publication.paths.push(prepared.destination.clone());
            if replace {
                // A verified reimport repairs truncated or otherwise different bytes.
                prepared
                    .file
                    .persist(&prepared.destination)
                    .map_err(|err| err.error)?;
            } else {
                prepared
                    .file
                    .persist_noclobber(&prepared.destination)
                    .map_err(|err| err.error)?;
            }
            directories.insert(parent);
        }
        for directory in directories {
            File::open(directory)?.sync_all()?;
        }
        publication.durable = true;
        Ok(())
    }
}

#[derive(Default)]
struct Publication {
    paths: Vec<PathBuf>,
    backups: HashMap<PathBuf, tempfile::NamedTempFile>,
    durable: bool,
}
impl Drop for Publication {
    fn drop(&mut self) {
        // Roll back new files and restore replacements. Backups are temporary files:
        // after a successful directory flush they may safely be cleaned on restart.
        for path in &self.paths {
            let failed = if self.durable {
                false
            } else if let Some(backup) = self.backups.get(path) {
                fs::rename(backup.path(), path)
                    .and_then(|()| File::open(path.parent().expect("sidecar parent"))?.sync_all())
                    .is_err()
            } else {
                fs::remove_file(path).is_err_and(|err| err.kind() != std::io::ErrorKind::NotFound)
            };
            let mut pending = PENDING.lock().unwrap_or_else(|err| err.into_inner());
            if failed {
                tracing::error!(?path, "Failed to roll back sidecar publication");
                pending.insert(path.clone(), true);
            } else {
                pending.remove(path);
            }
        }
    }
}

/// Startup only, before any writers start. Never run this during live pruning: a tempfile
/// could still belong to an active write. `.tmp` covers files from the previous implementation.
pub(crate) fn cleanup_temporary_sidecars(directory: &Path) -> Result<(), StoreError> {
    let mut removed = false;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if entry.file_type()?.is_file()
            && (name.starts_with(TEMP_PREFIX) || name.starts_with(".tmp"))
        {
            fs::remove_file(entry.path())?;
            removed = true;
        }
    }
    if removed {
        File::open(directory)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn batch_publication_preserves_duplicates_and_cleans_staging() {
        let dir = tempdir::TempDir::new("sidecar_batch").unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        PreparedSidecarFile::publish_batch(vec![
            PreparedSidecarFile::new(a.clone(), b"first").unwrap(),
            PreparedSidecarFile::new(b.clone(), b"second").unwrap(),
        ])
        .unwrap();
        PreparedSidecarFile::new(a.clone(), b"first")
            .unwrap()
            .publish()
            .unwrap();
        assert_eq!(fs::read(&a).unwrap(), b"first");
        assert!(open_published(&b).unwrap().is_some());
        fs::write(dir.path().join(".ream-sidecar-orphan"), b"partial").unwrap();
        cleanup_temporary_sidecars(dir.path()).unwrap();
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }
    #[test]
    fn reimport_repairs_truncated_file() {
        let dir = tempdir::TempDir::new("sidecar_repair").unwrap();
        let path = dir.path().join("column");
        fs::write(&path, b"truncated").unwrap();
        PreparedSidecarFile::new(path.clone(), b"verified complete file")
            .unwrap()
            .publish()
            .unwrap();
        assert_eq!(fs::read(path).unwrap(), b"verified complete file");
    }

    #[test]
    fn failed_repair_batch_restores_existing_file() {
        let dir = tempdir::TempDir::new("sidecar_repair_failure").unwrap();
        let path = dir.path().join("a");
        fs::write(&path, b"previous").unwrap();
        let replacement = PreparedSidecarFile::new(path.clone(), b"replacement").unwrap();
        let nested = dir.path().join("nested");
        fs::create_dir(&nested).unwrap();
        let failing = PreparedSidecarFile::new(nested.join("b"), b"new").unwrap();
        fs::remove_dir_all(nested).unwrap();
        assert!(PreparedSidecarFile::publish_batch(vec![replacement, failing]).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"previous");
        assert!(open_published(&path).unwrap().is_some());
    }

    #[test]
    fn failed_batch_does_not_hide_files_or_leave_partial_publications() {
        let dir = tempdir::TempDir::new("sidecar_failure").unwrap();
        let a = dir.path().join("a");
        let first = PreparedSidecarFile::new(a.clone(), b"first").unwrap();
        let nested = dir.path().join("nested");
        fs::create_dir(&nested).unwrap();
        let second = PreparedSidecarFile::new(nested.join("b"), b"second").unwrap();
        fs::remove_dir_all(&nested).unwrap();
        assert!(PreparedSidecarFile::publish_batch(vec![first, second]).is_err());
        assert!(open_published(&a).unwrap().is_none());
        PreparedSidecarFile::new(a.clone(), b"retry")
            .unwrap()
            .publish()
            .unwrap();
        assert!(open_published(&a).unwrap().is_some());
    }
}
