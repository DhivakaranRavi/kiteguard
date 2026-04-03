use std::process::Command;

fn main() {
    // Only build the Vue console when the console/ directory exists.
    // This allows `cargo build` to succeed before the Vue project is scaffolded.
    let dashboard = std::path::Path::new("console");
    if !dashboard.exists() {
        println!("cargo:warning=console/ not found — skipping npm build");
        return;
    }

    // Tell cargo to re-run this script when Vue source files change
    println!("cargo:rerun-if-changed=console/src");
    println!("cargo:rerun-if-changed=console/index.html");
    println!("cargo:rerun-if-changed=console/package.json");
    println!("cargo:rerun-if-changed=console/vite.config.js");

    // On Windows, npm is a .cmd batch file and Rust's Command::new won't find it
    // without the extension — use npm.cmd explicitly on that platform.
    #[cfg(windows)]
    let npm = "npm.cmd";
    #[cfg(not(windows))]
    let npm = "npm";

    // Install node_modules if not present
    let node_modules = dashboard.join("node_modules");
    if !node_modules.exists() {
        let status = Command::new(npm)
            .args(["ci", "--prefer-offline", "--ignore-scripts"])
            .current_dir(dashboard)
            .status()
            .expect("npm ci failed — is Node.js installed?");
        if !status.success() {
            panic!("npm ci exited with non-zero status");
        }
    }

    // Build the Vue app
    let status = Command::new(npm)
        .args(["run", "build"])
        .current_dir(dashboard)
        .status()
        .expect("npm run build failed");
    if !status.success() {
        panic!("npm run build exited with non-zero status");
    }
}
