//! Writing to standard output without dying when the reader goes away.
//!
//! Rust sets `SIGPIPE` to be ignored before `main` runs, so a write to a closed
//! pipe comes back as `EPIPE` instead of killing the process — and `println!`
//! turns that into a panic:
//!
//! ```text
//! $ bbiwy list | head -3
//! thread 'main' panicked at library/std/src/io/stdio.rs
//! failed printing to stdout: Broken pipe (os error 32)
//! ```
//!
//! Restoring the default signal disposition means a raw `signal()` call, and
//! `unsafe` is forbidden in this crate, so the condition is handled where it
//! appears instead. A closed pipe is the reader saying it has seen enough; that
//! is a normal, silent end, not an error worth printing.

use std::io::{self, Write};

/// Writes `s` followed by a newline.
pub fn line(s: &str) -> Result<(), String> {
    write(s.as_bytes())?;
    write(b"\n")
}

/// Writes `s` exactly as given, with no newline added.
pub fn text(s: &str) -> Result<(), String> {
    write(s.as_bytes())
}

fn write(bytes: &[u8]) -> Result<(), String> {
    match io::stdout().lock().write_all(bytes) {
        Ok(()) => Ok(()),
        // The reader is gone. Stop quietly, the way a shell pipeline expects.
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(e) => Err(format!("could not write to stdout: {e}")),
    }
}
