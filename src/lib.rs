//! Run a program in an OS sandbox, without a container.
//!
//! ```no_run
//! let sandbox = gelada::Sandbox::new()?          // reads everything but common secrets
//!     .allow_write("/path/to/project")           // writes only here (and its temp folder)
//!     .network(false);                           // no network
//! let status = sandbox.command("make")?.arg("build").status()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! The sandbox is applied as the program starts, so it also holds for
//! everything the program starts. A sandboxed program:
//!
//! - reads everything except the denied paths, which start as
//!   [`common_secrets`] (`~/.ssh`, cloud credentials, other tools' tokens);
//! - writes only the folders you allow, plus a temporary folder of its own
//!   (`TMPDIR`), removed when the [`Sandbox`] is dropped;
//! - has the network only when you turn it on;
//! - doesn't see environment variables that look like credentials
//!   ([`looks_like_a_credential`]) unless you keep them.
//!
//! Platforms: macOS (Seatbelt), Linux (Landlock and seccomp). Windows is
//! planned; until then [`Sandbox::command`] returns [`Error::Unsupported`].
//! gelada never falls back to running a program unsandboxed.
//!
//! What it does not protect against is in the README's threat model.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

/// Secrets most machines have, relative to the home folder: keys, cloud and
/// deploy credentials, package registry and git tokens, password stores.
pub const COMMON_SECRETS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".config/gcloud",
    ".kube",
    ".docker/config.json",
    ".npmrc",
    ".yarnrc.yml",
    ".netrc",
    ".git-credentials",
    ".config/git/credentials",
    ".config/gh",
    ".config/op",
    ".password-store",
    ".wrangler",
    ".config/.wrangler",
    "Library/Keychains",
    "Library/Preferences/.wrangler",
];

/// [`COMMON_SECRETS`] under `home`.
pub fn common_secrets(home: &Path) -> Vec<PathBuf> {
    COMMON_SECRETS.iter().map(|secret| home.join(secret)).collect()
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("gelada can't sandbox programs on this platform yet (Windows is planned)")]
    Unsupported,
    #[error("the sandbox isn't available here: {0}")]
    Unavailable(String),
    #[error("{0}: {1}")]
    Io(PathBuf, std::io::Error),
}

/// What a sandboxed program may do. Build it, then call
/// [`Sandbox::command`] for each program; keep it until they end, since
/// their temporary folder goes when it does.
#[derive(Debug, Clone)]
pub struct Sandbox {
    denied: Vec<PathBuf>,
    writable: Vec<PathBuf>,
    network: bool,
    keep_env: Vec<String>,
    temp: Arc<TempFolder>,
}

impl Sandbox {
    /// Reads everything but [`common_secrets`], writes only its temporary
    /// folder, no network, credentials filtered from the environment.
    pub fn new() -> Result<Self, Error> {
        let home = std::env::var_os("HOME")
            .filter(|home| !home.is_empty())
            .map(PathBuf::from);
        let mut sandbox = Self::empty()?;
        if let Some(home) = home {
            sandbox.denied = common_secrets(&home);
        }
        Ok(sandbox)
    }

    /// Like [`Sandbox::new`] but denying nothing: for callers that build
    /// their own list with [`Sandbox::deny`].
    pub fn empty() -> Result<Self, Error> {
        let temp = std::env::temp_dir().join(format!(
            "gelada-{}-{}",
            std::process::id(),
            unique()
        ));
        std::fs::create_dir_all(&temp).map_err(|err| Error::Io(temp.clone(), err))?;
        Ok(Self {
            denied: Vec::new(),
            writable: Vec::new(),
            network: false,
            keep_env: Vec::new(),
            temp: Arc::new(TempFolder(temp)),
        })
    }

    /// Neither readable nor writable, even inside an allowed folder.
    pub fn deny(mut self, path: impl Into<PathBuf>) -> Self {
        self.denied.push(path.into());
        self
    }

    /// Lifts a denial: `path` and everything under it become readable (and
    /// writable, if inside an allowed folder) again.
    pub fn undeny(mut self, path: impl AsRef<Path>) -> Self {
        let path = path.as_ref();
        self.denied.retain(|denied| !denied.starts_with(path));
        self
    }

    /// Writable, with everything under it (except denied paths). It is
    /// created if it doesn't exist.
    pub fn allow_write(mut self, path: impl Into<PathBuf>) -> Self {
        self.writable.push(path.into());
        self
    }

    pub fn network(mut self, on: bool) -> Self {
        self.network = on;
        self
    }

    /// Passes this variable through even though it looks like a credential.
    pub fn keep_env(mut self, name: impl Into<String>) -> Self {
        self.keep_env.push(name.into());
        self
    }

    /// The denied paths.
    pub fn denied(&self) -> &[PathBuf] {
        &self.denied
    }

    /// The writable folders, including the temporary folder.
    pub fn writable(&self) -> Vec<PathBuf> {
        let mut paths = self.writable.clone();
        paths.push(self.temp.0.clone());
        paths
    }

    pub fn has_network(&self) -> bool {
        self.network
    }

    /// The program's temporary folder (its `TMPDIR`).
    pub fn temp_dir(&self) -> &Path {
        &self.temp.0
    }

    /// A [`Command`] that runs `program` in this sandbox, with a filtered
    /// environment and `TMPDIR` set to the sandbox's temporary folder.
    pub fn command(&self, program: impl AsRef<OsStr>) -> Result<Command, Error> {
        let mut command = self.platform_command(program.as_ref())?;
        command.env_clear();
        for (name, value) in std::env::vars_os() {
            let Some(text) = name.to_str() else { continue };
            if !looks_like_a_credential(text) || self.keep_env.iter().any(|keep| keep == text) {
                command.env(&name, value);
            }
        }
        command.env("TMPDIR", self.temp_dir());
        Ok(command)
    }

    #[cfg(target_os = "macos")]
    fn platform_command(&self, program: &OsStr) -> Result<Command, Error> {
        macos::command(self, program)
    }

    #[cfg(target_os = "linux")]
    fn platform_command(&self, program: &OsStr) -> Result<Command, Error> {
        linux::command(self, program)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn platform_command(&self, _program: &OsStr) -> Result<Command, Error> {
        Err(Error::Unsupported)
    }
}

/// Environment variables a program shouldn't see by default: tokens, keys,
/// passwords, cloud credentials and the ssh agent.
pub fn looks_like_a_credential(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    const WORDS: [&str; 7] = [
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "CREDENTIAL",
        "API_KEY",
        "APIKEY",
    ];
    const PREFIXES: [&str; 4] = ["AWS_", "AZURE_", "GOOGLE_APPLICATION_", "NPM_CONFIG__AUTH"];
    const EXACT: [&str; 2] = ["SSH_AUTH_SOCK", "NODE_AUTH_TOKEN"];
    WORDS.iter().any(|word| upper.contains(word))
        || PREFIXES.iter().any(|prefix| upper.starts_with(prefix))
        || EXACT.contains(&upper.as_str())
        || upper.ends_with("_KEY")
        || upper.ends_with("_AUTH")
}

/// A temporary folder removed when the last [`Sandbox`] holding it goes.
#[derive(Debug)]
struct TempFolder(PathBuf);

impl Drop for TempFolder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `path` with symlinks resolved, also when it doesn't exist yet (its
/// nearest existing ancestor is resolved and the rest appended). Seatbelt
/// and Landlock both match real paths: /tmp is /private/tmp on macOS.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn real_path(path: &Path) -> PathBuf {
    let mut missing = Vec::new();
    let mut current = path;
    loop {
        if let Ok(real) = std::fs::canonicalize(current) {
            return missing.iter().rev().fold(real, |acc, part| acc.join(part));
        }
        match (current.parent(), current.file_name()) {
            (Some(parent), Some(name)) => {
                missing.push(name.to_os_string());
                current = parent;
            }
            _ => return path.to_path_buf(),
        }
    }
}

fn unique() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_are_recognised_by_name() {
        for name in [
            "GITHUB_TOKEN",
            "NPM_TOKEN",
            "AWS_ACCESS_KEY_ID",
            "STRIPE_SECRET",
            "OPENAI_API_KEY",
            "SSH_AUTH_SOCK",
            "DEPLOY_KEY",
            "npm_config__auth",
        ] {
            assert!(looks_like_a_credential(name), "{name}");
        }
        for name in ["PATH", "HOME", "LANG", "TERM", "CI", "NODE_ENV", "PLAYWRIGHT_BROWSERS_PATH"] {
            assert!(!looks_like_a_credential(name), "{name}");
        }
    }

    #[test]
    fn undeny_lifts_a_denial_and_what_is_under_it() {
        let sandbox = Sandbox::empty()
            .unwrap()
            .deny("/h/.ssh")
            .deny("/h/.config/gh")
            .deny("/h/.aws")
            .undeny("/h/.config");
        assert_eq!(sandbox.denied(), [PathBuf::from("/h/.ssh"), PathBuf::from("/h/.aws")]);
    }

    #[test]
    fn the_temporary_folder_goes_with_the_last_copy() {
        let sandbox = Sandbox::empty().unwrap();
        let temp = sandbox.temp_dir().to_path_buf();
        let copy = sandbox.clone();
        drop(sandbox);
        assert!(temp.is_dir());
        drop(copy);
        assert!(!temp.exists());
    }
}
