# Meridian

A Linux disk I/O monitoring and reporting tool that tracks I/O operations, bandwidth, and latency per process using eBPF.

## Overview

Meridian uses eBPF kprobes to intercept VFS layer read/write operations, capturing:
- Process ID and command name
- I/O operation type (read/write)
- Bytes transferred
- Operation latency
- Timestamps

Events can be filtered by process command name (comm) to focus on specific applications.

## Requirements

- Linux kernel with eBPF support (5.4+)
- Rust stable toolchain
- Rust nightly toolchain (for eBPF compilation)
- `bpf-linker` for linking eBPF programs
- Root privileges (or CAP_BPF + CAP_PERFMON) for loading eBPF programs

## Setup

Install the BPF linker:

```sh
cargo install bpf-linker
```

Ensure nightly toolchain is available:

```sh
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
```

## Building

Build the entire project (including eBPF probes):

```sh
cargo build
```

The eBPF probes are automatically compiled via `build.rs` using the nightly toolchain.

## Testing

Tests require root privileges to load eBPF programs:

```sh
sudo -E $(which cargo) test --test vfs_probe
```

With output:

```sh
sudo -E $(which cargo) test --test vfs_probe -- --nocapture
```

## Running

Run the meridian CLI:

```sh
sudo ./target/debug/meridian --bpf-path ./target/bpf/meridian-probes
```

With comm filtering (only monitor `dd` processes):

```sh
sudo ./target/debug/meridian --bpf-path ./target/bpf/meridian-probes --comm dd
```

With a custom OTLP gRPC endpoint for metrics export (defaults to `http://localhost:4317`):

```sh
sudo ./target/debug/meridian --bpf-path ./target/bpf/meridian-probes --otlp-endpoint http://otel-collector:4317
```

## Project Structure

```
meridian/
├── meridian/           # User-space agent and CLI
│   ├── src/
│   │   ├── lib.rs      # Library: load_and_attach, read_events
│   │   ├── main.rs     # CLI binary
│   │   └── bin/        # Helper binaries
│   ├── tests/          # Integration tests
│   └── build.rs        # eBPF build script
├── meridian-common/    # Shared types (no_std compatible)
│   └── src/lib.rs      # VfsEvent, IoOp, COMM_LEN
├── meridian-ebpf/      # eBPF probes (built for bpfel-unknown-none)
│   └── src/main.rs     # kprobe/kretprobe for vfs_read/vfs_write
└── SPECIFICATION.md    # Detailed project specification
```

## Specification

See [SPECIFICATION.md](SPECIFICATION.md) for detailed design documentation.

## License

MIT
