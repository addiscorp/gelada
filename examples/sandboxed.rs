//! Runs a command in a sandbox that may write the current folder:
//! `cargo run --example sandboxed -- [--net] <program> [args]`.

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let net = args.first().is_some_and(|arg| arg == "--net");
    if net {
        args.remove(0);
    }
    let Some(program) = args.first().cloned() else {
        eprintln!("usage: sandboxed [--net] <program> [args]");
        std::process::exit(2);
    };
    let sandbox = gelada::Sandbox::new()
        .unwrap()
        .allow_write(std::env::current_dir().unwrap())
        .network(net);
    let status = sandbox
        .command(&program)
        .unwrap_or_else(|err| panic!("{err}"))
        .args(&args[1..])
        .status()
        .unwrap();
    // Exiting skips destructors: remove the temporary folder first.
    drop(sandbox);
    std::process::exit(status.code().unwrap_or(1));
}
