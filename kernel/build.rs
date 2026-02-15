use std::env;
use std::fs::OpenOptions;
use std::io::{self, Seek, SeekFrom, Write};
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../userland/Cargo.toml");
    println!("cargo:rerun-if-changed=../userland/src");
    println!("cargo:rerun-if-changed=../userland/target/x86_64-unknown-none/debug/aurora-userland");
    println!(
        "cargo:rerun-if-changed=../userland/target/x86_64-unknown-none/release/aurora-userland"
    );

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR missing");
    let img_path = Path::new(&out_dir).join("ramdisk.img");
    create_ramdisk(&img_path).expect("ramdisk image generation failed");
}

fn create_ramdisk(path: &Path) -> io::Result<()> {
    const IMAGE_SIZE: u64 = 64 * 1024 * 1024;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)?;
    file.set_len(IMAGE_SIZE)?;
    file.seek(SeekFrom::Start(0))?;

    let mut stream = fscommon::BufStream::new(file);
    fatfs::format_volume(
        &mut stream,
        fatfs::FormatVolumeOptions::new().fat_type(fatfs::FatType::Fat32),
    )?;

    let fs = fatfs::FileSystem::new(stream, fatfs::FsOptions::new())?;
    let root = fs.root_dir();

    root.create_dir("HELLO")?;
    let mut readme = root.create_file("README.TXT")?;
    readme.write_all(b"aurora ramdisk\n")?;
    readme.flush()?;

    let mut nested = root.create_file("HELLO/README.TXT")?;
    nested.write_all(b"nested file\n")?;
    nested.flush()?;

    Ok(())
}
