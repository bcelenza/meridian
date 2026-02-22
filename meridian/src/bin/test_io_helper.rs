//! Test helper binary for precise I/O testing.
//!
//! Sets its process comm to a specific name and performs exactly one I/O operation.
//! This allows integration tests to filter for a unique comm and capture only
//! the expected I/O event.
//!
//! Usage:
//!   test_io_helper <comm> read <file> <bytes>
//!   test_io_helper <comm> read_direct <file> <bytes>  # O_DIRECT bypass cache (cache miss)
//!   test_io_helper <comm> read_twice <file> <bytes>   # Read twice (second is cache hit)
//!   test_io_helper <comm> write <file> <bytes>

use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::process::ExitCode;

fn set_comm(name: &str) -> std::io::Result<()> {
    // PR_SET_NAME = 15
    const PR_SET_NAME: libc::c_int = 15;

    // Comm is limited to 16 bytes including null terminator
    let mut comm_bytes = [0u8; 16];
    let name_bytes = name.as_bytes();
    let len = name_bytes.len().min(15);
    comm_bytes[..len].copy_from_slice(&name_bytes[..len]);

    let result = unsafe { libc::prctl(PR_SET_NAME, comm_bytes.as_ptr()) };

    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn do_read(file: &mut File, bytes: usize) -> std::io::Result<()> {
    use std::io::Seek;
    file.seek(std::io::SeekFrom::Start(0))?;
    let mut buffer = vec![0u8; bytes];
    file.read_exact(&mut buffer)?;
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if args.len() != 5 {
        eprintln!(
            "Usage: {} <comm> <read|read_direct|read_twice|write> <file> <bytes>",
            args.first().map(|s| s.as_str()).unwrap_or("test_io_helper")
        );
        return ExitCode::from(1);
    }

    let comm = &args[1];
    let operation = &args[2];
    let file_path = &args[3];
    let bytes: usize = match args[4].parse() {
        Ok(n) => n,
        Err(_) => {
            eprintln!("Invalid byte count: {}", args[4]);
            return ExitCode::from(1);
        }
    };

    // Set our comm name first
    if let Err(e) = set_comm(comm) {
        eprintln!("Failed to set comm: {}", e);
        return ExitCode::from(1);
    }

    match operation.as_str() {
        "read" => {
            let mut file = match File::open(file_path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to open file: {}", e);
                    return ExitCode::from(1);
                }
            };

            if let Err(e) = do_read(&mut file, bytes) {
                eprintln!("Failed to read: {}", e);
                return ExitCode::from(1);
            }
        }
        "read_direct" => {
            // Use O_DIRECT to bypass page cache (guaranteed cache miss from eBPF perspective)
            // Need null-terminated path for libc::open
            let c_path = std::ffi::CString::new(file_path.as_str()).unwrap();
            
            let fd = unsafe {
                libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_DIRECT)
            };

            if fd < 0 {
                eprintln!("Failed to open with O_DIRECT: {}", std::io::Error::last_os_error());
                return ExitCode::from(1);
            }

            // O_DIRECT requires page-aligned buffers
            use std::alloc::{alloc, dealloc, Layout};
            let align = 4096;
            let size = bytes.div_ceil(align) * align; // Round up to alignment
            let layout = match Layout::from_size_align(size, align) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("Failed to create layout: {}", e);
                    unsafe { libc::close(fd) };
                    return ExitCode::from(1);
                }
            };

            let buffer = unsafe { alloc(layout) };
            if buffer.is_null() {
                eprintln!("Failed to allocate aligned buffer");
                unsafe { libc::close(fd) };
                return ExitCode::from(1);
            }

            let result = unsafe { libc::read(fd, buffer as *mut libc::c_void, size) };

            unsafe {
                dealloc(buffer, layout);
                libc::close(fd);
            }

            if result < 0 {
                eprintln!("Failed to read: {}", std::io::Error::last_os_error());
                return ExitCode::from(1);
            }
        }
        "read_twice" => {
            // Read twice: first may be hit or miss, second is guaranteed hit
            let mut file = match File::open(file_path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to open file: {}", e);
                    return ExitCode::from(1);
                }
            };

            // First read
            if let Err(e) = do_read(&mut file, bytes) {
                eprintln!("Failed to read (first): {}", e);
                return ExitCode::from(1);
            }

            // Second read (guaranteed cache hit)
            if let Err(e) = do_read(&mut file, bytes) {
                eprintln!("Failed to read (second): {}", e);
                return ExitCode::from(1);
            }
        }
        "write" => {
            let mut file = match File::create(file_path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to create file: {}", e);
                    return ExitCode::from(1);
                }
            };

            let buffer = vec![0x42u8; bytes]; // Fill with 'B'
            match file.write_all(&buffer) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("Failed to write: {}", e);
                    return ExitCode::from(1);
                }
            }

            // Ensure data is flushed
            if let Err(e) = file.sync_all() {
                eprintln!("Failed to sync: {}", e);
                return ExitCode::from(1);
            }
        }
        _ => {
            eprintln!(
                "Unknown operation: {} (use 'read', 'read_direct', 'read_twice', or 'write')",
                operation
            );
            return ExitCode::from(1);
        }
    }

    ExitCode::SUCCESS
}
