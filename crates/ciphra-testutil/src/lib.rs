//! Test-only helpers shared across Ciphra crates. Never a runtime
//! dependency of the database itself.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A directory under the system temp dir, removed on drop.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Create a unique temporary directory for a test.
pub fn tempdir() -> TempDir {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before 1970")
        .subsec_nanos();
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "ciphra-test-{}-{}-{}",
        std::process::id(),
        unique,
        nanos
    ));
    std::fs::create_dir_all(&path).expect("failed to create temp dir");
    TempDir { path }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_unique_dirs_and_cleans_up() {
        let a = tempdir();
        let b = tempdir();
        assert_ne!(a.path(), b.path());
        assert!(a.path().is_dir());
        let path = a.path().to_path_buf();
        std::fs::write(path.join("f"), b"x").unwrap();
        drop(a);
        assert!(!path.exists());
    }
}
