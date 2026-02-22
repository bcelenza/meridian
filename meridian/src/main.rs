//! Meridian user-space agent.
//!
//! This binary loads and attaches the eBPF probes, then consumes events
//! from the ring buffer and outputs them.

use anyhow::Result;
use aya::maps::RingBuf;
use clap::Parser;
use log::{info, warn};
use meridian::{comm_to_string, load_and_attach, op_to_str};
use meridian_common::VfsEvent;
use std::path::PathBuf;
use tokio::signal;

#[derive(Debug, Parser)]
#[command(name = "meridian", about = "Linux disk I/O monitoring tool")]
pub struct Args {
    /// Path to the eBPF object file
    #[arg(short, long)]
    pub bpf_path: PathBuf,

    /// Optional process name (comm) to filter events
    #[arg(short, long)]
    pub comm: Option<String>,
}

/// Process events from the ring buffer.
pub async fn process_events(bpf: &mut aya::Ebpf) -> Result<()> {
    let ring_buf = RingBuf::try_from(bpf.map_mut("EVENTS").unwrap())?;
    let mut poll = tokio::io::unix::AsyncFd::new(ring_buf)?;

    info!("Listening for VFS I/O events... Press Ctrl+C to stop.");

    loop {
        let mut guard = poll.readable_mut().await?;
        let ring_buf = guard.get_inner_mut();

        while let Some(item) = ring_buf.next() {
            if item.len() >= std::mem::size_of::<VfsEvent>() {
                let event: VfsEvent =
                    unsafe { std::ptr::read_unaligned(item.as_ptr() as *const _) };
                let cache_status = if event.op == 0 {
                    // Only show cache status for reads
                    if event.cache_hit != 0 {
                        " cache=hit"
                    } else {
                        " cache=miss"
                    }
                } else {
                    ""
                };
                println!(
                    "pid={} comm={} op={} bytes={} latency_ns={}{} ts={}",
                    event.pid,
                    comm_to_string(&event.comm),
                    op_to_str(event.op),
                    event.bytes,
                    event.latency_ns,
                    cache_status,
                    event.timestamp_ns,
                );
            }
        }

        guard.clear_ready();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    let mut bpf = load_and_attach(&args.bpf_path, args.comm.as_deref())?;

    tokio::select! {
        result = process_events(&mut bpf) => {
            if let Err(e) = result {
                warn!("Event processing error: {}", e);
            }
        }
        _ = signal::ctrl_c() => {
            info!("Received Ctrl+C, shutting down...");
        }
    }

    Ok(())
}
