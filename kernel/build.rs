fn main() {
    println!("cargo:rerun-if-changed=../userland/Cargo.toml");
    println!("cargo:rerun-if-changed=../userland/src");
    println!(
        "cargo:rerun-if-changed=../userland/target/x86_64-unknown-none/debug/aurora-userland"
    );
    println!(
        "cargo:rerun-if-changed=../userland/target/x86_64-unknown-none/release/aurora-userland"
    );
}
