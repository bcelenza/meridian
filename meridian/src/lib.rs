//! Meridian library - core functionality for loading eBPF and processing events.

use anyhow::{Context, Result};
use aya::{maps::RingBuf, programs::KProbe, Ebpf};
use aya_log::EbpfLogger;
use log::{debug, info};
use meridian_common::{VfsEvent, COMM_LEN};
use std::path::Path;

/// Convert a string to a fixed-size comm buffer.
fn string_to_comm(s: &str) -> [u8; COMM_LEN] {
    let mut comm = [0u8; COMM_LEN];
    let bytes = s.as_bytes();
    let len = bytes.len().min(COMM_LEN - 1); // Leave room for null terminator
    comm[..len].copy_from_slice(&bytes[..len]);
    comm
}

/// Load and attach eBPF programs, returning the Ebpf handle.
///
/// If `filter_comm` is Some, only events from processes with that command name
/// will be captured.
pub fn load_and_attach(bpf_path: &Path, filter_comm: Option<&str>) -> Result<Ebpf> {
    let data = std::fs::read(bpf_path)
        .with_context(|| format!("Failed to read eBPF object file: {:?}", bpf_path))?;

    let mut bpf = Ebpf::load(&data).context("Failed to load eBPF program")?;

    // Initialize eBPF logger (optional, may fail if no log maps)
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        debug!(
            "Failed to initialize eBPF logger (this is usually fine): {}",
            e
        );
    }

    // Set comm filter if specified
    if let Some(comm) = filter_comm {
        let comm_bytes = string_to_comm(comm);
        let mut comm_filter: aya::maps::HashMap<_, u32, [u8; COMM_LEN]> =
            aya::maps::HashMap::try_from(bpf.map_mut("COMM_FILTER").unwrap())?;
        comm_filter.insert(0, comm_bytes, 0)?;
        info!("Filtering events for comm '{}'", comm);
    }

    // Attach kprobe and kretprobe for vfs_read
    let vfs_read_entry: &mut KProbe = bpf
        .program_mut("vfs_read_entry")
        .context("Failed to find vfs_read_entry program")?
        .try_into()?;
    vfs_read_entry.load()?;
    vfs_read_entry.attach("vfs_read", 0)?;
    info!("Attached kprobe to vfs_read");

    let vfs_read_exit: &mut KProbe = bpf
        .program_mut("vfs_read_exit")
        .context("Failed to find vfs_read_exit program")?
        .try_into()?;
    vfs_read_exit.load()?;
    vfs_read_exit.attach("vfs_read", 0)?;
    info!("Attached kretprobe to vfs_read");

    // Attach kprobe and kretprobe for vfs_write
    let vfs_write_entry: &mut KProbe = bpf
        .program_mut("vfs_write_entry")
        .context("Failed to find vfs_write_entry program")?
        .try_into()?;
    vfs_write_entry.load()?;
    vfs_write_entry.attach("vfs_write", 0)?;
    info!("Attached kprobe to vfs_write");

    let vfs_write_exit: &mut KProbe = bpf
        .program_mut("vfs_write_exit")
        .context("Failed to find vfs_write_exit program")?
        .try_into()?;
    vfs_write_exit.load()?;
    vfs_write_exit.attach("vfs_write", 0)?;
    info!("Attached kretprobe to vfs_write");

    Ok(bpf)
}

/// Format a comm buffer as a string.
pub fn comm_to_string(comm: &[u8; COMM_LEN]) -> String {
    let len = comm.iter().position(|&c| c == 0).unwrap_or(COMM_LEN);
    String::from_utf8_lossy(&comm[..len]).to_string()
}

/// Format operation type.
pub fn op_to_str(op: u8) -> &'static str {
    match op {
        0 => "read",
        1 => "write",
        _ => "unknown",
    }
}

/// Read available events from the ring buffer.
/// Returns a vector of events that were available.
pub fn read_events(bpf: &mut Ebpf) -> Result<Vec<VfsEvent>> {
    let mut ring_buf = RingBuf::try_from(bpf.map_mut("EVENTS").unwrap())?;
    let mut events = Vec::new();

    while let Some(item) = ring_buf.next() {
        if item.len() >= std::mem::size_of::<VfsEvent>() {
            let event: VfsEvent = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const _) };
            events.push(event);
        }
    }

    Ok(events)
}
