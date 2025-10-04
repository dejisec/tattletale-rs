use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result};
use memmap2::Mmap;

/// Threshold in bytes above which we attempt to use mmap for reading.
/// Callers can override via API; this is a reasonable default.
pub const DEFAULT_MMAP_THRESHOLD_BYTES: u64 = 16 * 1024 * 1024; // 16 MiB

pub type LineIter = Box<dyn Iterator<Item = io::Result<String>> + Send + 'static>;

/// Decide whether to use mmap based on file size and threshold.
pub fn should_use_mmap(file_size_bytes: u64, threshold_bytes: u64) -> bool {
    file_size_bytes >= threshold_bytes
}

/// Iterate lines from a file path using buffered reader (non-mmap).
pub fn iter_lines_bufread<P: AsRef<Path>>(path: P) -> Result<LineIter> {
    let file = File::open(&path).with_context(|| format!("open {}", path.as_ref().display()))?;
    let reader = BufReader::new(file);
    let lines = reader.lines();
    Ok(Box::new(lines))
}

/// Iterate lines from a file path using mmap. This avoids copying but still
/// allocates per-returned String; it scans for '\n' boundaries.
pub fn iter_lines_mmap<P: AsRef<Path>>(path: P) -> Result<LineIter> {
    let file = File::open(&path).with_context(|| format!("open {}", path.as_ref().display()))?;
    let mmap =
        unsafe { Mmap::map(&file) }.with_context(|| format!("mmap {}", path.as_ref().display()))?;
    let iter = MmapLines { mmap, pos: 0 };
    Ok(Box::new(iter))
}

struct MmapLines {
    mmap: Mmap,
    pos: usize,
}

impl Iterator for MmapLines {
    type Item = io::Result<String>;
    fn next(&mut self) -> Option<Self::Item> {
        let data: &[u8] = &self.mmap;
        if self.pos >= data.len() {
            return None;
        }
        let start = self.pos;
        // Find next newline
        if let Some(off) = memchr::memchr(b'\n', &data[self.pos..]) {
            let end = self.pos + off;
            self.pos = end + 1; // skip newline
            Some(line_from_bytes(&data[start..end]))
        } else {
            // Last line without trailing newline
            self.pos = data.len();
            Some(line_from_bytes(&data[start..]))
        }
    }
}

fn line_from_bytes(bytes: &[u8]) -> io::Result<String> {
    // Trim a trailing '\r' if present (handle Windows CRLF)
    let slice = if bytes.ends_with(b"\r") {
        &bytes[..bytes.len() - 1]
    } else {
        bytes
    };
    match std::str::from_utf8(slice) {
        Ok(s) => Ok(s.to_string()),
        Err(_) => Ok(String::from_utf8_lossy(slice).to_string()),
    }
}

/// Choose mmap or bufread and return an iterator over lines.
pub fn iter_lines_auto<P: AsRef<Path>>(path: P, threshold_bytes: u64) -> Result<LineIter> {
    let meta =
        std::fs::metadata(&path).with_context(|| format!("stat {}", path.as_ref().display()))?;
    if meta.is_file() && should_use_mmap(meta.len(), threshold_bytes) {
        iter_lines_mmap(path)
    } else {
        iter_lines_bufread(path)
    }
}
