use std::process::Command;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=../sntl_db/src/main.zig");
    println!("cargo:rerun-if-changed=../sntl_db/build.zig");

    let status = Command::new("zig")
        .args(["build", "-Doptimize=ReleaseSafe"])
        .current_dir("../sntl_db")
        .status()
        .expect("Failed to execute Zig compiler");

    if !status.success() {
        panic!("Compilation of the sntl_db Zig module failed");
    }

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let zig_lib_path = Path::new(&manifest_dir).join("../sntl_db/zig-out/lib");

    println!("cargo:rustc-link-search=native={}", zig_lib_path.display());
    println!("cargo:rustc-link-lib=static=sntl_db");
}