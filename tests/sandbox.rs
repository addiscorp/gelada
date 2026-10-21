//! Real programs in the real sandbox: what they can read, write, reach and
//! see. The "home" is a temporary folder holding fake secrets; the programs
//! are /bin/sh and curl. Every test here fails if the sandbox is skipped.

#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Output;

use gelada::Sandbox;

struct World {
    _root: tempfile::TempDir,
    home: PathBuf,
    project: PathBuf,
    outside: PathBuf,
}

fn world() -> World {
    let root = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(root.path()).unwrap();
    let home = base.join("home");
    let project = base.join("project");
    let outside = base.join("outside");
    for dir in [&home.join(".ssh"), &home.join(".config/gh"), &project, &outside, &home.join(".cache")] {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::fs::write(home.join(".ssh/id_ed25519"), "PRIVATE KEY").unwrap();
    std::fs::write(home.join(".config/gh/hosts.yml"), "oauth_token: gho_x").unwrap();
    std::fs::write(home.join(".npmrc"), "//registry.npmjs.org/:_authToken=npm_x").unwrap();
    std::fs::write(home.join("notes.txt"), "not a secret").unwrap();
    std::fs::write(project.join("package.json"), "{}").unwrap();
    World { _root: root, home, project, outside }
}

/// Denies the fake home's secrets (the real ones too, via `new`).
fn sandbox(w: &World) -> Sandbox {
    gelada::common_secrets(&w.home)
        .into_iter()
        .fold(Sandbox::new().unwrap(), Sandbox::deny)
}

fn sh(sandbox: &Sandbox, script: &str) -> Output {
    sandbox
        .command("/bin/sh")
        .unwrap()
        .arg("-c")
        .arg(script)
        .output()
        .unwrap()
}

fn ok(output: &Output) -> bool {
    output.status.success()
}

fn quote(path: &Path) -> String {
    format!("'{}'", path.display())
}

#[test]
fn reads_everything_but_secrets() {
    let w = world();
    let sandbox = sandbox(&w);
    let notes = sh(&sandbox, &format!("cat {}", quote(&w.home.join("notes.txt"))));
    assert!(ok(&notes), "{notes:?}");
    assert_eq!(String::from_utf8_lossy(&notes.stdout), "not a secret");
    for secret in [".ssh/id_ed25519", ".config/gh/hosts.yml", ".npmrc"] {
        let out = sh(&sandbox, &format!("cat {}", quote(&w.home.join(secret))));
        assert!(!ok(&out), "{secret} was readable: {out:?}");
        assert!(out.stdout.is_empty());
    }
}

#[test]
fn undeny_makes_a_secret_readable_again() {
    let w = world();
    let sandbox = sandbox(&w).undeny(w.home.join(".config/gh"));
    let gh = sh(&sandbox, &format!("cat {}", quote(&w.home.join(".config/gh/hosts.yml"))));
    assert!(ok(&gh), "{gh:?}");
    let ssh = sh(&sandbox, &format!("cat {}", quote(&w.home.join(".ssh/id_ed25519"))));
    assert!(!ok(&ssh), "{ssh:?}");
}

#[test]
fn a_child_of_the_program_is_sandboxed_too() {
    let w = world();
    let nested = format!("/bin/sh -c \"cat {}\"", w.home.join(".ssh/id_ed25519").display());
    let out = sh(&sandbox(&w), &nested);
    assert!(!ok(&out), "{out:?}");
}

#[test]
fn writes_only_allowed_folders_and_its_temp() {
    let w = world();
    let sandbox = sandbox(&w).allow_write(&w.project);
    let inside = sh(&sandbox, &format!("echo built > {}", quote(&w.project.join("out.txt"))));
    assert!(ok(&inside), "{inside:?}");
    let temp = sh(&sandbox, "echo t > \"$TMPDIR/t.txt\"");
    assert!(ok(&temp), "{temp:?}");
    for target in [
        w.outside.join("x.txt"),
        w.home.join(".bashrc"),
        w.home.join(".ssh/authorized_keys"),
    ] {
        let out = sh(&sandbox, &format!("echo pwned > {}", quote(&target)));
        assert!(!ok(&out), "wrote {}: {out:?}", target.display());
    }
}

#[test]
fn a_writable_folder_still_hides_the_secrets_inside_it() {
    let w = world();
    // The writable folder is the home folder: secrets sit inside it.
    let sandbox = sandbox(&w).allow_write(&w.home);
    let notes = sh(&sandbox, &format!("echo edited > {}", quote(&w.home.join("notes.txt"))));
    assert!(ok(&notes), "{notes:?}");
    let key = sh(&sandbox, &format!("echo pwned >> {}", quote(&w.home.join(".ssh/id_ed25519"))));
    assert!(!ok(&key), "{key:?}");
    assert_eq!(std::fs::read_to_string(w.home.join(".ssh/id_ed25519")).unwrap(), "PRIVATE KEY");
}

#[test]
fn the_network_is_off_until_turned_on() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            use std::io::{Read, Write};
            let mut stream = stream.unwrap();
            let _ = stream.read(&mut [0; 1024]);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok");
        }
    });
    let fetch = format!("curl -sS --max-time 5 http://127.0.0.1:{port}/");
    let w = world();
    let off = sh(&sandbox(&w), &fetch);
    assert!(!ok(&off), "{off:?}");
    let on = sh(&sandbox(&w).network(true), &fetch);
    assert!(ok(&on), "{on:?}");
    assert_eq!(String::from_utf8_lossy(&on.stdout), "ok");
}

#[test]
fn credentials_are_not_in_the_environment() {
    let w = world();
    let script = "echo \"t=$GITHUB_TOKEN k=$OPENAI_API_KEY p=$PATH_TEST keep=$KEEP_TOKEN\"";
    // SAFETY: no other test in this file reads these variables.
    unsafe {
        std::env::set_var("GITHUB_TOKEN", "ghp_secret");
        std::env::set_var("OPENAI_API_KEY", "sk-secret");
        std::env::set_var("PATH_TEST", "visible");
        std::env::set_var("KEEP_TOKEN", "kept");
    }
    let out = sh(&sandbox(&w), script);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "t= k= p=visible keep=");
    let out = sh(&sandbox(&w).keep_env("KEEP_TOKEN"), script);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "t= k= p=visible keep=kept");
}
