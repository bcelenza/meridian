//! Integration tests for the VFS layer eBPF probe.
//!
//! These tests require:
//! - Linux kernel with eBPF support
//! - Root privileges (or CAP_BPF + CAP_PERFMON)
//! - The eBPF program to be built first
//!
//! Run with: sudo -E cargo test --test vfs_probe

use anyhow::Result;
use meridian::{comm_to_string, load_and_attach, read_events};
use meridian_common::IoOp;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;
use tempfile::tempdir;

/// Get the path to the eBPF binary.
/// First checks the environment variable, then falls back to the default build location.
fn get_ebpf_path() -> PathBuf {
    if let Ok(path) = std::env::var("MERIDIAN_EBPF_PATH") {
        return PathBuf::from(path);
    }

    // Default location after building
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .join("target")
        .join("bpfel-unknown-none")
        .join("release")
        .join("meridian-probes")
}

/// Get the path to the test_io_helper binary.
fn get_helper_path() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .join("target")
        .join("debug")
        .join("test_io_helper")
}

/// Test that the eBPF program loads and attaches successfully.
#[test]
fn test_ebpf_load_and_attach() -> Result<()> {
    let ebpf_path = get_ebpf_path();

    if !ebpf_path.exists() {
        panic!(
            "eBPF binary not found at {:?}. Build with: \
             cd meridian-ebpf && cargo +nightly build --release \
             -Z build-std=core --target bpfel-unknown-none",
            ebpf_path
        );
    }

    // Load without comm filter
    let bpf = load_and_attach(&ebpf_path, None)?;
    drop(bpf);

    Ok(())
}

/// Test that VFS read events are captured with comm filtering.
/// Uses test_io_helper subprocess with a unique comm for precise testing.
#[test]
fn test_vfs_read_captures_comm() -> Result<()> {
    let ebpf_path = get_ebpf_path();
    let helper_path = get_helper_path();

    if !ebpf_path.exists() {
        panic!("eBPF binary not found at {:?}", ebpf_path);
    }
    if !helper_path.exists() {
        panic!(
            "test_io_helper binary not found at {:?}. Build with: cargo build",
            helper_path
        );
    }

    // Create a temp file with known content
    let dir = tempdir()?;
    let file_path = dir.path().join("test_read.txt");
    let test_bytes = 100usize;
    let test_data = vec![0x42u8; test_bytes];
    std::fs::write(&file_path, &test_data)?;

    // Use a unique comm for this test
    let filter_comm = "mrd_read_test";

    // Load with comm filter
    let mut bpf = load_and_attach(&ebpf_path, Some(filter_comm))?;

    // Small delay to ensure probes are fully attached
    thread::sleep(Duration::from_millis(100));

    // Use helper to read exactly test_bytes from the file
    let status = Command::new(&helper_path)
        .arg(filter_comm)
        .arg("read")
        .arg(&file_path)
        .arg(test_bytes.to_string())
        .status()?;

    assert!(status.success(), "test_io_helper read command failed");

    // Give the ring buffer time to be populated
    thread::sleep(Duration::from_millis(100));

    // Read events
    let events = read_events(&mut bpf)?;

    println!("Total events captured: {}", events.len());
    for (i, e) in events.iter().enumerate() {
        println!(
            "  Event {}: pid={} comm='{}' op={} bytes={}",
            i,
            e.pid,
            comm_to_string(&e.comm),
            if e.op == 0 { "read" } else { "write" },
            e.bytes
        );
    }

    // Should have exactly one read event with our exact byte count
    let read_events: Vec<_> = events
        .iter()
        .filter(|e| e.op == IoOp::Read as u8 && comm_to_string(&e.comm) == filter_comm)
        .collect();

    assert_eq!(
        read_events.len(),
        1,
        "Expected exactly 1 read event from comm '{}', got {}",
        filter_comm,
        read_events.len()
    );

    let event = read_events[0];
    assert_eq!(comm_to_string(&event.comm), filter_comm);
    assert_eq!(event.op, IoOp::Read as u8);
    assert_eq!(
        event.bytes, test_bytes as u64,
        "Expected exactly {} bytes read",
        test_bytes
    );
    assert!(event.latency_ns > 0, "Expected non-zero latency");

    println!(
        "Captured read event: pid={} comm={} bytes={} latency_ns={}",
        event.pid,
        comm_to_string(&event.comm),
        event.bytes,
        event.latency_ns
    );

    Ok(())
}

/// Test that VFS write events are captured with comm filtering.
/// Uses test_io_helper subprocess with a unique comm for precise testing.
#[test]
fn test_vfs_write_captures_comm() -> Result<()> {
    let ebpf_path = get_ebpf_path();
    let helper_path = get_helper_path();

    if !ebpf_path.exists() {
        panic!("eBPF binary not found at {:?}", ebpf_path);
    }
    if !helper_path.exists() {
        panic!(
            "test_io_helper binary not found at {:?}. Build with: cargo build",
            helper_path
        );
    }

    // Create a temp directory for output
    let dir = tempdir()?;
    let file_path = dir.path().join("test_write.txt");
    let test_bytes = 50usize;

    // Use a unique comm for this test
    let filter_comm = "mrd_write_test";

    // Load with comm filter
    let mut bpf = load_and_attach(&ebpf_path, Some(filter_comm))?;

    // Small delay to ensure probes are fully attached
    thread::sleep(Duration::from_millis(100));

    // Use helper to write exactly test_bytes to the file
    let status = Command::new(&helper_path)
        .arg(filter_comm)
        .arg("write")
        .arg(&file_path)
        .arg(test_bytes.to_string())
        .status()?;

    assert!(status.success(), "test_io_helper write command failed");

    // Give the ring buffer time to be populated
    thread::sleep(Duration::from_millis(100));

    // Read events
    let events = read_events(&mut bpf)?;

    println!("Total events captured: {}", events.len());
    for (i, e) in events.iter().enumerate() {
        println!(
            "  Event {}: pid={} comm='{}' op={} bytes={}",
            i,
            e.pid,
            comm_to_string(&e.comm),
            if e.op == 0 { "read" } else { "write" },
            e.bytes
        );
    }

    // Should have exactly one write event with our exact byte count
    let write_events: Vec<_> = events
        .iter()
        .filter(|e| e.op == IoOp::Write as u8 && comm_to_string(&e.comm) == filter_comm)
        .collect();

    assert_eq!(
        write_events.len(),
        1,
        "Expected exactly 1 write event from comm '{}', got {}",
        filter_comm,
        write_events.len()
    );

    let event = write_events[0];
    assert_eq!(comm_to_string(&event.comm), filter_comm);
    assert_eq!(event.op, IoOp::Write as u8);
    assert_eq!(
        event.bytes, test_bytes as u64,
        "Expected exactly {} bytes written",
        test_bytes
    );
    assert!(event.latency_ns > 0, "Expected non-zero latency");

    println!(
        "Captured write event: pid={} comm={} bytes={} latency_ns={}",
        event.pid,
        comm_to_string(&event.comm),
        event.bytes,
        event.latency_ns
    );

    Ok(())
}

/// Test that comm filtering works correctly (other processes are filtered out).
/// Uses test_io_helper with one comm but filters for a different comm.
#[test]
fn test_comm_filter_excludes_other_processes() -> Result<()> {
    let ebpf_path = get_ebpf_path();
    let helper_path = get_helper_path();

    if !ebpf_path.exists() {
        panic!("eBPF binary not found at {:?}", ebpf_path);
    }
    if !helper_path.exists() {
        panic!(
            "test_io_helper binary not found at {:?}. Build with: cargo build",
            helper_path
        );
    }

    // Create a temp file with enough data
    let dir = tempdir()?;
    let file_path = dir.path().join("test_filter.txt");
    std::fs::write(&file_path, vec![0x42u8; 50])?; // 50 bytes

    // Filter for a comm that won't be used
    let filter_comm = "nonexistent";
    // But run the helper with a different comm
    let actual_comm = "mrd_excluded";

    // Load with comm filter for the non-matching comm
    let mut bpf = load_and_attach(&ebpf_path, Some(filter_comm))?;

    // Small delay to ensure probes are fully attached
    thread::sleep(Duration::from_millis(100));

    // Run helper with a comm that should be filtered out
    let status = Command::new(&helper_path)
        .arg(actual_comm)
        .arg("read")
        .arg(&file_path)
        .arg("50") // Read 50 bytes
        .status()?;

    assert!(status.success(), "test_io_helper command failed");

    // Give the ring buffer time
    thread::sleep(Duration::from_millis(100));

    // Read events
    let events = read_events(&mut bpf)?;

    println!("Total events captured: {}", events.len());
    for (i, e) in events.iter().enumerate() {
        println!(
            "  Event {}: pid={} comm='{}' op={} bytes={}",
            i,
            e.pid,
            comm_to_string(&e.comm),
            if e.op == 0 { "read" } else { "write" },
            e.bytes
        );
    }

    // We should have no events since the comm doesn't match the filter
    let helper_events: Vec<_> = events
        .iter()
        .filter(|e| comm_to_string(&e.comm) == actual_comm)
        .collect();

    assert!(
        helper_events.is_empty(),
        "Expected no events from '{}' when filtered for '{}', but got {} events",
        actual_comm,
        filter_comm,
        helper_events.len()
    );

    println!(
        "Correctly filtered out all '{}' events (filter was '{}')",
        actual_comm, filter_comm
    );

    Ok(())
}
