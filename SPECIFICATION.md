# Meridian Specification

## Overview

Meridian is a Linux disk I/O monitoring tool that uses eBPF to observe and report on disk activity per process. It consists of two components:

1. **eBPF Program** — Kernel-space probes that capture I/O events with minimal overhead.
2. **User-space Agent** — Consumes eBPF event data and produces logs and metrics.

The implementation uses the [Aya](https://aya-rs.dev/) Rust library for both the eBPF programs and the user-space agent.

## Architecture

```
┌─────────────────────────────────────────────┐
│                  Kernel                      │
│                                             │
│  ┌─────────┐    ┌──────────┐    ┌────────┐  │
│  │  VFS    │───▶│  Block   │───▶│  Disk  │  │
│  │  Layer  │    │  Layer   │    │        │  │
│  └────┬────┘    └────┬─────┘    └────────┘  │
│       │              │                       │
│  ┌────┴────┐    ┌────┴─────┐                │
│  │  eBPF   │    │  eBPF    │                │
│  │  Probe  │    │  Probe   │                │
│  └────┬────┘    └────┬─────┘                │
│       │              │                       │
│       ▼              ▼                       │
│     ┌──────────────────┐                    │
│     │  BPF Ring Buffer │                    │
│     └────────┬─────────┘                    │
└──────────────┼──────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────┐
│           User-space Agent                   │
│                                              │
│  ┌──────────┐  ┌──────────┐  ┌────────────┐ │
│  │  Event   │  │  Metric  │  │   Output   │ │
│  │  Reader  │─▶│  Agg.    │─▶│   (TBD)    │ │
│  └──────────┘  └──────────┘  └────────────┘ │
└──────────────────────────────────────────────┘
```

## eBPF Probes

### VFS Layer

Attach to VFS operations to capture all I/O requests, including those served from page cache:

- `vfs_read` / `vfs_write` — entry and return probes

Captured data:
- PID and comm (process name)
- Operation type (read/write)
- Byte count (requested and actual)
- Timestamps (entry and exit, for latency calculation)

### Block Layer

Attach to block I/O operations to identify requests that reach physical disk:

- `block_rq_issue` / `block_rq_complete` — tracepoints

Captured data:
- PID (where attributable)
- Sector, size
- Timestamps (for device-level latency)

### Cache Detection

An I/O is considered **cached** if it completes at the VFS layer without a corresponding block layer request. An I/O that results in a block layer request is considered a **disk hit**.

## Event Data

Each I/O event emitted to user-space contains:

| Field          | Type     | Description                                  |
|----------------|----------|----------------------------------------------|
| `pid`          | u32      | Process ID                                   |
| `comm`         | [u8; 16] | Process command name                         |
| `op`           | u8       | Operation type (read=0, write=1)             |
| `bytes`        | u64      | Bytes transferred                            |
| `latency_ns`   | u64      | Operation latency in nanoseconds             |
| `cached`       | bool     | Whether the I/O was served from page cache   |
| `timestamp_ns` | u64      | Event timestamp (monotonic clock)            |

## User-space Agent

### Metrics Produced

Per PID, the agent tracks and reports:

1. **I/O Operation Count** — Total read and write operations.
2. **Throughput** — Bytes per second (read/write), computed per operation and as a rolling aggregate.
3. **Latency** — Per-operation latency, emitted as a distrubution type when used for metrics.
4. **I/O Timing** — Wall-clock timing of when I/O operations occurred.
5. **Cache Hit Ratio** — Percentage of operations served from page cache vs. disk.

### Output

- **Logs**: Structured logs emitted to stdout in real-time (one line per I/O event). Future support planned for offloading to external sinks via OTLP (e.g., Azure Data Explorer or Splunk).
- **Metrics**: Exported via OpenTelemetry (OTLP).
- **Mode**: Real-time — each I/O event is emitted as it occurs.

## Scope & Filtering

- **Default**: Monitor all processes system-wide.
- **Optional PID filter**: One or more PIDs can be specified via CLI arguments to restrict monitoring.
- **I/O types**: Only regular file I/O (disk-backed files). Socket, pipe, and other non-file I/O is excluded.
- eBPF probes filter at the kernel level when a PID filter is active, minimizing overhead.
