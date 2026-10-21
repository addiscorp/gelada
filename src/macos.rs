//! Seatbelt: the program runs under `/usr/bin/sandbox-exec` with a profile
//! built from the forked base policy (closed by default) plus gelada's
//! rules. Paths go in as `-D` parameters, never pasted into the profile.

use std::ffi::OsStr;
use std::process::Command;

use crate::{Error, Sandbox, real_path};

/// Only the system's copy: a sandbox-exec found on PATH could be anything.
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

const BASE: &str = include_str!("seatbelt_base.sbpl");
const NETWORK: &str = include_str!("seatbelt_network.sbpl");

/// The profile and its parameters for `sandbox`.
pub(crate) fn profile(sandbox: &Sandbox) -> (String, Vec<(String, String)>) {
    let mut profile = String::from(BASE);
    let mut params = Vec::new();

    // Read everything (compilers, SDKs, git) but the secrets below.
    profile.push_str("\n; gelada\n(allow file-read*)\n");
    // Paths some programs open by name for their standard streams.
    profile.push_str("(allow file-write-data (literal \"/dev/stdout\") (literal \"/dev/stderr\") (regex #\"^/dev/fd/[0-9]+$\"))\n");

    for (index, path) in sandbox.writable().iter().enumerate() {
        let key = format!("WRITE_{index}");
        profile.push_str(&format!("(allow file-write* (subpath (param \"{key}\")))\n"));
        params.push((key, real_path(path).to_string_lossy().into_owned()));
    }

    // Later rules win: the secrets are carved out of everything above.
    for (index, path) in sandbox.denied().iter().enumerate() {
        let key = format!("SECRET_{index}");
        profile.push_str(&format!(
            "(deny file-read* file-write* (subpath (param \"{key}\")))\n"
        ));
        params.push((key, real_path(path).to_string_lossy().into_owned()));
    }

    if sandbox.has_network() {
        profile.push_str(NETWORK);
        profile.push_str("\n(allow network-outbound)\n(allow network-inbound)\n");
    }
    (profile, params)
}

pub(crate) fn command(sandbox: &Sandbox, program: &OsStr) -> Result<Command, Error> {
    if !std::path::Path::new(SANDBOX_EXEC).is_file() {
        return Err(Error::Unavailable(format!("{SANDBOX_EXEC} is missing")));
    }
    let (profile, params) = profile(sandbox);
    let mut command = Command::new(SANDBOX_EXEC);
    command.arg("-p").arg(profile);
    for (key, value) in params {
        command.arg("-D").arg(format!("{key}={value}"));
    }
    command.arg("--").arg(program);
    Ok(command)
}
