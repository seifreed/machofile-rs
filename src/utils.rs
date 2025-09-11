//! Utility functions for Mach-O parsing

use crate::errors::{Error, Result};
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Calculate entropy of a byte slice
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequency = HashMap::new();
    for &byte in data {
        *frequency.entry(byte).or_insert(0) += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in frequency.values() {
        let prob = count as f64 / len;
        if prob > 0.0 {
            entropy -= prob * prob.log2();
        }
    }

    entropy
}

/// Read a null-terminated C string from a byte slice
pub fn read_cstring(data: &[u8], offset: usize) -> Result<String> {
    if offset >= data.len() {
        return Err(Error::InvalidOffset(offset));
    }

    let slice = &data[offset..];
    let null_pos = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    let string_bytes = &slice[..null_pos];

    String::from_utf8(string_bytes.to_vec()).map_err(Error::StringError)
}

/// Read a fixed-size string from a byte array
pub fn read_fixed_string(bytes: &[u8]) -> String {
    let null_pos = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..null_pos]).to_string()
}

/// Read u32 with endianness detection
pub fn read_u32(data: &[u8], offset: usize, is_little_endian: bool) -> Result<u32> {
    if offset + 4 > data.len() {
        return Err(Error::InvalidOffset(offset));
    }

    let bytes = &data[offset..offset + 4];
    Ok(if is_little_endian {
        LittleEndian::read_u32(bytes)
    } else {
        BigEndian::read_u32(bytes)
    })
}

/// Read u64 with endianness detection
pub fn read_u64(data: &[u8], offset: usize, is_little_endian: bool) -> Result<u64> {
    if offset + 8 > data.len() {
        return Err(Error::InvalidOffset(offset));
    }

    let bytes = &data[offset..offset + 8];
    Ok(if is_little_endian {
        LittleEndian::read_u64(bytes)
    } else {
        BigEndian::read_u64(bytes)
    })
}

/// Read i32 with endianness detection
pub fn read_i32(data: &[u8], offset: usize, is_little_endian: bool) -> Result<i32> {
    if offset + 4 > data.len() {
        return Err(Error::InvalidOffset(offset));
    }

    let bytes = &data[offset..offset + 4];
    Ok(if is_little_endian {
        LittleEndian::read_i32(bytes)
    } else {
        BigEndian::read_i32(bytes)
    })
}

/// Calculate MD5 hash
pub fn calculate_md5(data: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Calculate SHA1 hash
pub fn calculate_sha1(data: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Calculate SHA256 hash
pub fn calculate_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Format version number from packed u32
pub fn format_version(version: u32) -> String {
    let major = (version >> 16) & 0xFFFF;
    let minor = (version >> 8) & 0xFF;
    let patch = version & 0xFF;
    format!("{}.{}.{}", major, minor, patch)
}

/// Format build version
pub fn format_build_version(version: u64) -> String {
    // Source version is encoded as A.B.C.D.E
    // where A is bits 63-40, B is bits 39-30, C is bits 29-20, D is bits 19-10, E is bits 9-0
    let a = (version >> 40) & 0xFFFFFF;
    let b = (version >> 30) & 0x3FF;
    let c = (version >> 20) & 0x3FF;
    let d = (version >> 10) & 0x3FF;
    let e = version & 0x3FF;

    if e != 0 {
        format!("{}.{}.{}.{}.{}", a, b, c, d, e)
    } else if d != 0 {
        format!("{}.{}.{}.{}", a, b, c, d)
    } else if c != 0 {
        format!("{}.{}.{}", a, b, c)
    } else {
        format!("{}.{}", a, b)
    }
}

/// Convert protection flags to string
pub fn format_protection(prot: u32) -> String {
    let mut result = String::new();

    if prot & 0x1 != 0 {
        result.push('r');
    } else {
        result.push('-');
    }
    if prot & 0x2 != 0 {
        result.push('w');
    } else {
        result.push('-');
    }
    if prot & 0x4 != 0 {
        result.push('x');
    } else {
        result.push('-');
    }

    result
}

/// Detect endianness from magic number
pub fn detect_endianness(magic: u32) -> (bool, bool) {
    match magic {
        0xFEEDFACE | 0xFEEDFACF | 0xCAFEBABE | 0xCAFEBABF => (false, false), // Big endian
        0xCEFAEDFE | 0xCFFAEDFE | 0xBEBAFECA | 0xBFBAFECA => (true, true),   // Little endian
        _ => (false, false),
    }
}

/// Check if magic number is valid
pub fn is_valid_magic(magic: u32) -> bool {
    matches!(
        magic,
        0xFEEDFACE
            | 0xCEFAEDFE
            | 0xFEEDFACF
            | 0xCFFAEDFE
            | 0xCAFEBABE
            | 0xBEBAFECA
            | 0xCAFEBABF
            | 0xBFBAFECA
    )
}

/// Check if magic number is for a FAT/Universal binary
pub fn is_fat_magic(magic: u32) -> bool {
    matches!(magic, 0xCAFEBABE | 0xBEBAFECA | 0xCAFEBABF | 0xBFBAFECA)
}

/// Check if magic number is for a 64-bit binary
pub fn is_64_bit_magic(magic: u32) -> bool {
    matches!(magic, 0xFEEDFACF | 0xCFFAEDFE | 0xCAFEBABF | 0xBFBAFECA)
}

/// Get architecture name from CPU type
pub fn get_arch_name(cpu_type: i32) -> String {
    use crate::constants::*;

    match cpu_type as u32 {
        CPU_TYPE_X86 => "x86".to_string(),
        CPU_TYPE_X86_64 => "x86_64".to_string(),
        CPU_TYPE_ARM => "arm".to_string(),
        CPU_TYPE_ARM64 => "arm64".to_string(),
        CPU_TYPE_PPC => "ppc".to_string(),
        CPU_TYPE_PPC64 => "ppc64".to_string(),
        _ => format!("unknown_{:#x}", cpu_type),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        let data = vec![0u8; 100];
        assert_eq!(calculate_entropy(&data), 0.0);

        let data = (0..256).map(|i| i as u8).collect::<Vec<_>>();
        let entropy = calculate_entropy(&data);
        assert!(entropy > 7.9 && entropy < 8.1);
    }

    #[test]
    fn test_cstring_reading() {
        let data = b"hello\0world\0";
        let s = read_cstring(data, 0).unwrap();
        assert_eq!(s, "hello");

        let s = read_cstring(data, 6).unwrap();
        assert_eq!(s, "world");
    }

    #[test]
    fn test_version_formatting() {
        assert_eq!(format_version(0x010203), "1.2.3");
        assert_eq!(format_version(0x0A0B0C), "10.11.12");
    }
}
