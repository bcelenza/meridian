# Meridian

Meridian is a Linux disk I/O monitoring and reporting tool that tracks I/O operations, bandwidth, and latency per process.

## Tech Stack

- **Language:** Rust
- **Target Platform:** Linux

## Project Structure

This is a Rust project managed with Cargo. The standard Rust project layout applies:

- `src/` — Application source code
- `tests/` — Integration tests
- `Cargo.toml` — Project manifest and dependencies

## Development Guidelines

- Use idiomatic Rust: prefer `Result` and `Option` over panics, leverage the type system, and follow Rust API guidelines.
- Write unit tests alongside source code (`#[cfg(test)]` modules) and integration tests in `tests/`.
- Use `clippy` for linting and `rustfmt` for formatting.
- Keep unsafe code to a minimum; document and justify any `unsafe` blocks.
- Prefer the standard library and well-maintained crates over hand-rolled solutions.
- See `SPECIFICATION.md` for implementation details.

## Building & Testing

```sh
cargo build          # Build the project
cargo test           # Run all tests
cargo clippy         # Lint
cargo fmt --check    # Check formatting
```
