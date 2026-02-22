//! Meridian eBPF probes for VFS layer I/O monitoring.
//!
//! This program attaches to `vfs_read` and `vfs_write` functions to capture
//! file I/O operations at the VFS layer.

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{kprobe, kretprobe, map},
    maps::{HashMap, RingBuf},
    programs::{ProbeContext, RetProbeContext},
};
use meridian_common::{IoOp, VfsEvent};

/// Ring buffer for sending events to user space.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Map to store entry timestamps for latency calculation.
/// Key: (pid, op) packed as u64, Value: timestamp_ns
#[map]
static ENTRY_TIMESTAMPS: HashMap<u64, u64> = HashMap::with_max_entries(10240, 0);

/// Optional comm filter. If set (non-zero first byte), only events from processes
/// with this command name are recorded.
/// Key: 0 (single entry), Value: target comm (16 bytes, null-terminated)
#[map]
static COMM_FILTER: HashMap<u32, [u8; 16]> = HashMap::with_max_entries(1, 0);

/// Pack PID and operation into a single u64 key.
#[inline(always)]
fn make_key(pid: u32, op: u8) -> u64 {
    ((pid as u64) << 8) | (op as u64)
}

/// Check if we should trace this process based on comm filter.
#[inline(always)]
fn should_trace(comm: &[u8; 16]) -> bool {
    match unsafe { COMM_FILTER.get(&0) } {
        Some(filter_comm) if filter_comm[0] != 0 => {
            // Compare comm strings
            for i in 0..16 {
                if filter_comm[i] != comm[i] {
                    return false;
                }
                // Stop at null terminator
                if filter_comm[i] == 0 {
                    break;
                }
            }
            true
        }
        _ => true, // No filter or filter disabled
    }
}

/// Common entry probe logic.
#[inline(always)]
fn handle_entry(_ctx: &ProbeContext, op: IoOp) -> u32 {
    // Get comm early for filtering
    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => return 0,
    };

    if !should_trace(&comm) {
        return 0;
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let ts = unsafe { bpf_ktime_get_ns() };
    let key = make_key(pid, op as u8);

    let _ = ENTRY_TIMESTAMPS.insert(&key, &ts, 0);
    0
}

/// Common return probe logic.
#[inline(always)]
fn handle_exit(ctx: &RetProbeContext, op: IoOp) -> u32 {
    // Get comm early for filtering
    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => return 0,
    };

    if !should_trace(&comm) {
        return 0;
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let key = make_key(pid, op as u8);

    let entry_ts = match unsafe { ENTRY_TIMESTAMPS.get(&key) } {
        Some(&ts) => ts,
        None => return 0,
    };

    let _ = ENTRY_TIMESTAMPS.remove(&key);

    let exit_ts = unsafe { bpf_ktime_get_ns() };
    let latency_ns = exit_ts.saturating_sub(entry_ts);

    // Get return value (bytes read/written, or negative error)
    let ret: i64 = ctx.ret().unwrap_or(-1);

    // Ignore errors (negative return values)
    if ret < 0 {
        return 0;
    }

    let bytes = ret as u64;

    // Reserve space in ring buffer and write event
    if let Some(mut entry) = EVENTS.reserve::<VfsEvent>(0) {
        let event = entry.as_mut_ptr();
        unsafe {
            (*event).pid = pid;
            (*event).comm = comm;
            (*event).op = op as u8;
            (*event)._pad = [0u8; 3];
            (*event).bytes = bytes;
            (*event).latency_ns = latency_ns;
            (*event).timestamp_ns = exit_ts;
        }
        entry.submit(0);
    }

    0
}

#[kprobe]
pub fn vfs_read_entry(ctx: ProbeContext) -> u32 {
    handle_entry(&ctx, IoOp::Read)
}

#[kretprobe]
pub fn vfs_read_exit(ctx: RetProbeContext) -> u32 {
    handle_exit(&ctx, IoOp::Read)
}

#[kprobe]
pub fn vfs_write_entry(ctx: ProbeContext) -> u32 {
    handle_entry(&ctx, IoOp::Write)
}

#[kretprobe]
pub fn vfs_write_exit(ctx: RetProbeContext) -> u32 {
    handle_exit(&ctx, IoOp::Write)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
