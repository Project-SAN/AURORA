{
  description = "AURORA Rust dev environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ rust-overlay.overlays.default ];
        pkgs = import nixpkgs { inherit system overlays; };
        lib = pkgs.lib;
        isLinux = pkgs.stdenv.isLinux;
        rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        qemuFirmwareDir = "${pkgs.qemu}/share/qemu";
        ovmf = if isLinux && pkgs ? OVMF then pkgs.OVMF else null;
        ovmfFd = if ovmf != null then (if ovmf ? fd then ovmf.fd else ovmf) else null;
      in {
        devShells.default = pkgs.mkShell ({
          packages = [
            rustToolchain
            pkgs.pkg-config
            pkgs.git
            pkgs.qemu
          ] ++ lib.optional (ovmf != null) ovmf;

          RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
          QEMU_FIRMWARE_DIR = "${qemuFirmwareDir}";
        } // lib.optionalAttrs (ovmfFd != null) {
          UEFI_CODE = "${ovmfFd}/FV/OVMF_CODE.fd";
          UEFI_VARS_TEMPLATE = "${ovmfFd}/FV/OVMF_VARS.fd";
        });
      }
    );
}
