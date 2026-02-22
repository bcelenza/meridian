//! Build script for meridian user-space agent.
//!
//! This script builds the eBPF program before the main crate.

use anyhow::{Context, Result};
use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() -> Result<()> {
    // Tell cargo to rerun if the eBPF source changes
    println!("cargo:rerun-if-changed=../meridian-ebpf/src/");
    println!("cargo:rerun-if-changed=../meridian-common/src/");

    let manifest_dir = env::var("CARGO_MANIFEST_DIR")?;
    let workspace_root = PathBuf::from(&manifest_dir).parent().unwrap().to_path_buf();
    let ebpf_dir = workspace_root.join("meridian-ebpf");
    let out_dir = env::var("OUT_DIR")?;

    // Determine target endianness for BPF
    let target = match env::var("CARGO_CFG_TARGET_ENDIAN")
        .as_deref()
        .unwrap_or("little")
    {
        "big" => "bpfeb-unknown-none",
        _ => "bpfel-unknown-none",
    };

    // Get target arch for BPF
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "x86_64".to_string());

    // Build the eBPF program
    let status = Command::new("rustup")
        .current_dir(&ebpf_dir)
        .env_remove("RUSTC")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env(
            "CARGO_ENCODED_RUSTFLAGS",
            format!(
                "--cfg=bpf_target_arch=\"{}\"\x1f-Cdebuginfo=2\x1f-Clink-arg=--btf",
                target_arch
            ),
        )
        .args([
            "run",
            "nightly",
            "cargo",
            "build",
            "--release",
            "-Z",
            "build-std=core",
            "--target",
            target,
            "--target-dir",
            &out_dir,
        ])
        .status()
        .context("Failed to run cargo build for eBPF program")?;

    if !status.success() {
        anyhow::bail!("Failed to build eBPF program");
    }

    // Set path to the built eBPF binary
    let ebpf_binary = PathBuf::from(&out_dir)
        .join(target)
        .join("release")
        .join("meridian-probes");

    // Copy to a predictable location in target directory
    let target_dir = workspace_root.join("target").join("bpf");
    std::fs::create_dir_all(&target_dir)?;
    let dest_path = target_dir.join("meridian-probes");
    std::fs::copy(&ebpf_binary, &dest_path).context("Failed to copy eBPF binary")?;

    println!("cargo:rustc-env=MERIDIAN_EBPF_PATH={}", dest_path.display());

    Ok(())
}
