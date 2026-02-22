//! Common types shared between the eBPF probes and user-space agent.
//!
//! This crate is `no_std` compatible so it can be used in eBPF programs.

#![no_std]

/// Maximum length of process command name.
pub const COMM_LEN: usize = 16;

/// I/O operation type.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoOp {
    Read = 0,
    Write = 1,
}

/// VFS I/O event emitted from the eBPF probe.
///
/// This struct is sent through the ring buffer from kernel to user space.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VfsEvent {
    /// Process ID that initiated the I/O.
    pub pid: u32,
    /// Process command name.
    pub comm: [u8; COMM_LEN],
    /// Operation type (read or write).
    pub op: u8,
    /// Padding for alignment.
    pub _pad: [u8; 3],
    /// Bytes transferred.
    pub bytes: u64,
    /// Operation latency in nanoseconds.
    pub latency_ns: u64,
    /// Event timestamp (monotonic clock, nanoseconds).
    pub timestamp_ns: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for VfsEvent {}
