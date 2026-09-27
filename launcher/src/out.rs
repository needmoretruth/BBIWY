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

/// A progress note on standard error, so that it never mixes into output a
/// script might be reading.
pub fn note(s: &str) {
    let _ = writeln!(io::stderr().lock(), "{s}");
}

/// CJK characters occupy two terminal columns. `{:<20}` counts characters, so
/// using it directly misaligns any table containing them.
pub fn pad(s: &str, width: usize) -> String {
    let w: usize = s.chars().map(char_width).sum();
    let mut out = s.to_string();
    for _ in w..width {
        out.push(' ');
    }
    out
}

fn char_width(c: char) -> usize {
    match c as u32 {
        0x1100..=0x115F
        | 0x2E80..=0xA4CF
        | 0xAC00..=0xD7A3
        | 0xF900..=0xFAFF
        | 0xFE30..=0xFE6F
        | 0xFF00..=0xFF60
        | 0xFFE0..=0xFFE6
        | 0x20000..=0x3FFFD => 2,
        _ => 1,
    }
}
