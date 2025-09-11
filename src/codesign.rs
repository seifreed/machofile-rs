//! Code signature and entitlements parsing

use crate::constants::*;
use crate::errors::{Error, Result};
use crate::structs::*;
use crate::utils::*;
use byteorder::{BigEndian, ByteOrder};

/// Parse code signature from LC_CODE_SIGNATURE load command
pub fn parse_code_signature(data: &[u8], dataoff: u32, datasize: u32) -> Result<CodeSignature> {
    let sig_start = dataoff as usize;
    let sig_end = sig_start + datasize as usize;

    if sig_end > data.len() {
        return Err(Error::InvalidOffset(sig_start));
    }

    let signature_data = &data[sig_start..sig_end];

    // Parse the SuperBlob
    if signature_data.len() < 12 {
        return Ok(CodeSignature {
            signed: false,
            signing_status: "Unsigned".to_string(),
            certificates: Vec::new(),
            entitlements: Vec::new(),
            code_directory: None,
        });
    }

    let magic = BigEndian::read_u32(&signature_data[0..4]);

    if magic != CSMAGIC_EMBEDDED_SIGNATURE && magic != CSMAGIC_EMBEDDED_SIGNATURE_OLD {
        return Ok(CodeSignature {
            signed: false,
            signing_status: "Invalid signature".to_string(),
            certificates: Vec::new(),
            entitlements: Vec::new(),
            code_directory: None,
        });
    }

    let _length = BigEndian::read_u32(&signature_data[4..8]);
    let count = BigEndian::read_u32(&signature_data[8..12]);

    let mut certificates = Vec::new();
    let mut entitlements = Vec::new();
    let mut code_directory = None;

    // Parse blob index
    for i in 0..count {
        let index_offset = 12 + (i as usize * 8);
        if index_offset + 8 > signature_data.len() {
            break;
        }

        let slot_type = BigEndian::read_u32(&signature_data[index_offset..index_offset + 4]);
        let blob_offset =
            BigEndian::read_u32(&signature_data[index_offset + 4..index_offset + 8]) as usize;

        if blob_offset >= signature_data.len() {
            continue;
        }

        match slot_type {
            CSSLOT_CODEDIRECTORY => {
                code_directory = parse_code_directory(&signature_data[blob_offset..]);
            }
            CSSLOT_ENTITLEMENTS => {
                entitlements = parse_entitlements(&signature_data[blob_offset..]);
            }
            CSSLOT_DER_ENTITLEMENTS => {
                // Parse DER entitlements if XML entitlements not found
                if entitlements.is_empty() {
                    entitlements = parse_der_entitlements(&signature_data[blob_offset..]);
                }
            }
            slot if slot >= CSSLOT_SIGNATURESLOT => {
                // Certificate slot
                if let Some(cert) =
                    parse_certificate(&signature_data[blob_offset..], certificates.len())
                {
                    certificates.push(cert);
                }
            }
            _ => {}
        }
    }

    // Determine signing status
    let signing_status = determine_signing_status(&certificates, &code_directory);

    Ok(CodeSignature {
        signed: true,
        signing_status,
        certificates,
        entitlements,
        code_directory,
    })
}

/// Parse Code Directory blob
fn parse_code_directory(data: &[u8]) -> Option<CodeDirectory> {
    if data.len() < 88 {
        return None;
    }

    let magic = BigEndian::read_u32(&data[0..4]);
    if magic != CSMAGIC_CODEDIRECTORY {
        return None;
    }

    let _length = BigEndian::read_u32(&data[4..8]);
    let version = BigEndian::read_u32(&data[8..12]);
    let flags = BigEndian::read_u32(&data[12..16]);
    let hash_offset = BigEndian::read_u32(&data[16..20]);
    let ident_offset = BigEndian::read_u32(&data[20..24]);
    let special_slots = BigEndian::read_u32(&data[24..28]);
    let code_slots = BigEndian::read_u32(&data[28..32]);
    let _code_limit = BigEndian::read_u32(&data[32..36]);
    let hash_size = data[36];
    let hash_type = data[37];

    // Parse identifier
    let identifier = if ident_offset > 0 && (ident_offset as usize) < data.len() {
        read_cstring(data, ident_offset as usize).unwrap_or_else(|_| String::new())
    } else {
        String::new()
    };

    // Determine hash algorithm
    let hash_algorithm = match hash_type {
        1 => "SHA-1",
        2 => "SHA-256",
        3 => "SHA-256 (truncated)",
        4 => "SHA-384",
        _ => "Unknown",
    }
    .to_string();

    Some(CodeDirectory {
        version,
        flags,
        hash_offset,
        identifier_offset: ident_offset,
        special_slots,
        code_slots,
        hash_size: hash_size as u32,
        hash_type: hash_type as u32,
        hash_algorithm,
        identifier,
        signing_flags: decode_signing_flags(flags),
    })
}

/// Decode code signing flags
fn decode_signing_flags(flags: u32) -> Vec<String> {
    let mut active_flags = Vec::new();

    if flags & 0x00000001 != 0 {
        active_flags.push("Host".to_string());
    }
    if flags & 0x00000002 != 0 {
        active_flags.push("Adhoc".to_string());
    }
    if flags & 0x00000100 != 0 {
        active_flags.push("Hard".to_string());
    }
    if flags & 0x00000200 != 0 {
        active_flags.push("Kill".to_string());
    }
    if flags & 0x00000400 != 0 {
        active_flags.push("CheckExpiration".to_string());
    }
    if flags & 0x00001000 != 0 {
        active_flags.push("Enforcement".to_string());
    }
    if flags & 0x00002000 != 0 {
        active_flags.push("RequireLV".to_string());
    }
    if flags & 0x00010000 != 0 {
        active_flags.push("Runtime".to_string());
    }
    if flags & 0x00020000 != 0 {
        active_flags.push("LinkerSigned".to_string());
    }

    if active_flags.is_empty() {
        active_flags.push("None".to_string());
    }

    active_flags
}

/// Parse entitlements (XML format)
fn parse_entitlements(data: &[u8]) -> Vec<String> {
    if data.len() < 8 {
        return Vec::new();
    }

    let magic = BigEndian::read_u32(&data[0..4]);
    if magic != CSMAGIC_EMBEDDED_ENTITLEMENTS {
        return Vec::new();
    }

    let length = BigEndian::read_u32(&data[4..8]) as usize;
    if length > data.len() {
        return Vec::new();
    }

    // Parse XML plist
    let xml_data = &data[8..length];
    parse_plist_entitlements(xml_data)
}

/// Parse DER encoded entitlements
fn parse_der_entitlements(data: &[u8]) -> Vec<String> {
    if data.len() < 8 {
        return Vec::new();
    }

    let magic = BigEndian::read_u32(&data[0..4]);
    if magic != CSMAGIC_EMBEDDED_DER_ENTITLEMENTS {
        return Vec::new();
    }

    // DER parsing is complex, return empty for now
    // In a full implementation, this would parse ASN.1 DER format
    Vec::new()
}

/// Parse plist XML to extract entitlement keys
fn parse_plist_entitlements(xml_data: &[u8]) -> Vec<String> {
    let xml_str = String::from_utf8_lossy(xml_data);
    let mut entitlements = Vec::new();

    // Simple XML parsing to extract keys
    // In a full implementation, use an XML parser
    for line in xml_str.lines() {
        if let Some(start) = line.find("<key>") {
            if let Some(end) = line.find("</key>") {
                let key = &line[start + 5..end];
                entitlements.push(key.to_string());
            }
        }
    }

    entitlements
}

/// Parse certificate blob
fn parse_certificate(data: &[u8], index: usize) -> Option<Certificate> {
    if data.len() < 8 {
        return None;
    }

    let magic = BigEndian::read_u32(&data[0..4]);
    if magic != CSMAGIC_BLOBWRAPPER {
        return None;
    }

    let length = BigEndian::read_u32(&data[4..8]) as usize;
    if length > data.len() {
        return None;
    }

    // Parse X.509 certificate
    // This is a simplified version - full implementation would use an X.509 parser
    let cert_data = &data[8..length];

    // Check for Apple certificate markers
    let cert_str = String::from_utf8_lossy(cert_data);
    let is_apple_cert = cert_str.contains("Apple")
        || cert_str.contains("Developer ID")
        || cert_str.contains("Mac App Store");

    let cert_type = if cert_str.contains("Apple Root CA") {
        "Apple Root CA"
    } else if cert_str.contains("Developer ID Certification Authority") {
        "Developer ID Certification Authority"
    } else if cert_str.contains("Developer ID Application") {
        "Developer ID Application Certificate"
    } else if cert_str.contains("Mac App Store") {
        "Mac App Store Certificate"
    } else if cert_str.contains("Apple Worldwide Developer Relations") {
        "Apple WWDR Certificate"
    } else {
        "Unknown Certificate"
    }
    .to_string();

    Some(Certificate {
        index,
        size: length - 8,
        subject: extract_certificate_field(&cert_str, "CN="),
        issuer: extract_certificate_field(&cert_str, "O="),
        is_apple_cert,
        cert_type,
    })
}

/// Extract field from certificate string
fn extract_certificate_field(cert_str: &str, field: &str) -> String {
    if let Some(start) = cert_str.find(field) {
        let remaining = &cert_str[start + field.len()..];
        if let Some(end) = remaining.find([',', '/', '\0']) {
            return remaining[..end].to_string();
        }
    }
    "Unable to parse".to_string()
}

/// Determine overall signing status
fn determine_signing_status(
    certificates: &[Certificate],
    code_directory: &Option<CodeDirectory>,
) -> String {
    if certificates.is_empty() && code_directory.is_none() {
        return "Unsigned".to_string();
    }

    if let Some(cd) = code_directory {
        let flags = &cd.signing_flags;

        if flags.contains(&"Adhoc".to_string()) {
            return "Ad-hoc signed".to_string();
        }

        if flags.contains(&"Runtime".to_string()) {
            return "Signed with runtime hardening".to_string();
        }

        if !certificates.is_empty() {
            let has_apple_cert = certificates.iter().any(|c| c.is_apple_cert);
            if has_apple_cert {
                return "Apple signed".to_string();
            } else {
                return "Developer signed".to_string();
            }
        }
    }

    if !certificates.is_empty() {
        return "Signed (certificate present)".to_string();
    }

    "Signed (code directory only)".to_string()
}
