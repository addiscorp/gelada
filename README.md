# gelada

Run a program in an OS sandbox, without a container.

```sh
cargo add gelada
```

```rust
let sandbox = gelada::Sandbox::new()?      // reads everything but common secrets
    .allow_write("/path/to/project")       // writes only here (and its own temp folder)
    .network(false);                       // no network
let status = sandbox.command("npm")?.args(["run", "build"]).status()?;
```

The sandbox is applied as the program starts, by the operating system, so it
holds for everything the program starts too: a shell, a script's
interpreter, a compiler. It costs nothing measurable at startup: no image,
no VM, no daemon.

A sandboxed program:

- **reads** everything except denied paths. These start as
  [`COMMON_SECRETS`](src/lib.rs): `~/.ssh`, `~/.aws`, `~/.config/gcloud`,
  `~/.kube`, `~/.docker/config.json`, `~/.npmrc`, `~/.netrc`, `~/.config/gh`,
  the macOS keychain and others. Add your own with `deny`; lift one with
  `undeny`.
- **writes** only the folders you allow, plus a temporary folder of its own
  (`TMPDIR`) that is removed when the `Sandbox` is dropped. Denied paths
  stay denied inside allowed folders.
- **has the network** only when you turn it on.
- **doesn't see** environment variables that look like credentials
  (`*TOKEN*`, `*SECRET*`, `*_KEY`, `AWS_*`, `SSH_AUTH_SOCK`, …) unless you
  `keep_env` them.

gelada was built for [Simien](https://github.com/simienapp/runtime), which
runs every package install script and every `s x <package>` in it, and is
useful anywhere you run code you didn't write: build tools, agents, CI steps.

## Platforms

| | mechanism | status |
|---|---|---|
| macOS | Seatbelt (`/usr/bin/sandbox-exec`) with a closed-by-default profile | supported |
| Linux | Landlock (kernel 5.13+) for files, seccomp for the network | supported |
| Windows | AppContainer and job objects | planned |

gelada **never falls back to running a program unsandboxed**. On Windows,
or on a Linux kernel without Landlock, `command` returns an error (or the
spawn fails) instead.

## Threat model

gelada is for running code you don't fully trust (a dependency's install
script, a tool fetched from a registry, a command an agent chose) on your own
machine, so that it can't take your secrets or change things outside the
folders you allowed.

It protects against a program, and anything it starts:

- reading your keys, tokens and credentials from their usual locations or
  from the environment;
- sending anything over the network when the network is off;
- writing outside the folders you allowed: your shell profile, other
  projects, `~/.ssh/authorized_keys`, git hooks elsewhere.

It does **not** protect against:

- **damage inside the folders you allowed.** A program allowed to write your
  project can delete or rewrite it.
- **secrets outside the denied paths.** A `.env` file in your project, a
  token in an unusual location: deny them, or keep them out of reach.
- **anything once the network is on.** On, the program can reach any host
  (per-host filtering is planned). With the network on and a readable
  secret, assume the secret can leave.
- **reading non-secret files.** Reads are open everywhere except denied
  paths, so a program can read your source code and other projects.
- **kernel or sandbox bugs.** A kernel exploit or a flaw in Seatbelt or
  Landlock escapes any sandbox of this kind. For that, use a VM.
- **resource abuse.** CPU, memory and disk are not limited.

On macOS, Seatbelt is formally deprecated by Apple but used by Chrome,
Bazel and others. The profile also leaves some system services reachable
that programs commonly need (user lookup, TLS trust evaluation when the
network is on); see [`src/seatbelt_base.sbpl`](src/seatbelt_base.sbpl).

On Linux, Landlock can only allow, not deny. "Everything but secrets" is
built by walking down from `/` and allowing each entry except the denied
ones; files created later next to a secret are covered only if their parent
was allowed whole. Network-off blocks IPv4 and IPv6 sockets and io_uring;
Unix sockets stay available.

Found a way out? See [SECURITY.md](SECURITY.md).

## License

Apache-2.0. The macOS base profile is forked from OpenAI Codex (Apache-2.0),
itself based on Chromium's; see [NOTICE](NOTICE).
