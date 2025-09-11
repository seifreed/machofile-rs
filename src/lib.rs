//! machofile - A Rust library to parse Mach-O binary files
//!
//! The Mach-O file format is the executable file format used by macOS, iOS, watchOS, and tvOS.
//! This module aims to provide parsing capability for Mach-O binaries with a focus on
//! malware analysis and reverse engineering.

pub mod api_compat;
pub mod codesign;
pub mod constants;
pub mod errors;
pub mod load_commands;
pub mod parser;
pub mod structs;
pub mod symbol_parser;
pub mod utils;

pub use errors::{Error, Result};
pub use parser::{LoadCommandData, MachO, UniversalMachO};
pub use structs::*;

use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Parse a Mach-O file from a file path
pub fn parse_file<P: AsRef<Path>>(path: P) -> Result<UniversalMachO> {
    let mut file = File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    parse_data(&data)
}

/// Parse a Mach-O file from raw data
pub fn parse_data(data: &[u8]) -> Result<UniversalMachO> {
    UniversalMachO::parse(data)
}
