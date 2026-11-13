use std::process::Command;

fn main() {
    // Allow CI (or any build environment) to inject the hash directly.
    // Falls back to running `git rev-parse --short HEAD` locally.
    let hash = std::env::var("STACKDOG_GIT_HASH").unwrap_or_else(|_| {
        Command::new("git")
            .args(["rev-parse", "--short", "HEAD"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".to_string())
    });

    println!("cargo:rustc-env=STACKDOG_GIT_HASH={hash}");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads/");
}
