//! Symbol table and export trie parsing

use crate::constants::*;
use crate::errors::{Error, Result};
use crate::structs::*;
use crate::utils::*;
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use std::collections::HashMap;

/// Parse imported symbols from the symbol table
pub fn parse_imported_symbols(
    data: &[u8],
    symtab: &SymtabCommand,
    dysymtab: &DysymtabCommand,
    dylibs: &[DylibInfo],
    is_little_endian: bool,
    is_64_bit: bool,
) -> Result<Vec<ImportedSymbol>> {
    let mut imports_by_dylib: HashMap<String, Vec<String>> = HashMap::new();

    // Initialize dylib map
    for dylib in dylibs {
        imports_by_dylib.insert(dylib.name.clone(), Vec::new());
    }
    imports_by_dylib.insert("<unknown>".to_string(), Vec::new());

    // Read string table
    let stroff = symtab.stroff as usize;
    let strsize = symtab.strsize as usize;

    if stroff + strsize > data.len() {
        return Err(Error::InvalidOffset(stroff));
    }

    let string_table = &data[stroff..stroff + strsize];

    // Parse undefined symbols (imports)
    let symoff = symtab.symoff as usize;
    let iundefsym = dysymtab.iundefsym as usize;
    let nundefsym = dysymtab.nundefsym as usize;

    let nlist_size = if is_64_bit { 16 } else { 12 };

    for i in 0..nundefsym {
        let sym_idx = iundefsym + i;
        let offset = symoff + (sym_idx * nlist_size);

        if offset + nlist_size > data.len() {
            continue;
        }

        let sym_data = &data[offset..offset + nlist_size];

        // Parse nlist entry
        let n_strx = read_u32(sym_data, 0, is_little_endian)?;
        let n_type = sym_data[4];
        let _n_sect = sym_data[5];
        let n_desc = read_u16(sym_data, 6, is_little_endian)?;

        // Skip if not an undefined external symbol
        if (n_type & N_TYPE) != N_UNDF || (n_type & N_EXT) == 0 {
            continue;
        }

        // Get symbol name
        if n_strx as usize >= string_table.len() {
            continue;
        }

        let symbol_name = read_cstring(string_table, n_strx as usize)?;

        // Determine which dylib this symbol comes from
        let dylib_ordinal = ((n_desc >> 8) & 0xFF) as usize;

        let dylib_name = if dylib_ordinal > 0 && dylib_ordinal <= dylibs.len() {
            &dylibs[dylib_ordinal - 1].name
        } else {
            "<unknown>"
        };

        imports_by_dylib
            .entry(dylib_name.to_string())
            .or_default()
            .push(symbol_name);
    }

    // Convert to ImportedSymbol structs
    let mut result = Vec::new();
    for (dylib, symbols) in imports_by_dylib {
        if !symbols.is_empty() {
            result.push(ImportedSymbol { dylib, symbols });
        }
    }

    Ok(result)
}

/// Parse exported symbols from the symbol table
pub fn parse_exported_symbols(
    data: &[u8],
    symtab: &SymtabCommand,
    dysymtab: &DysymtabCommand,
    is_little_endian: bool,
    is_64_bit: bool,
) -> Result<Vec<String>> {
    let mut exports = Vec::new();

    // Read string table
    let stroff = symtab.stroff as usize;
    let strsize = symtab.strsize as usize;

    if stroff + strsize > data.len() {
        return Err(Error::InvalidOffset(stroff));
    }

    let string_table = &data[stroff..stroff + strsize];

    // Parse externally defined symbols (exports)
    let symoff = symtab.symoff as usize;
    let iextdefsym = dysymtab.iextdefsym as usize;
    let nextdefsym = dysymtab.nextdefsym as usize;

    let nlist_size = if is_64_bit { 16 } else { 12 };

    for i in 0..nextdefsym {
        let sym_idx = iextdefsym + i;
        let offset = symoff + (sym_idx * nlist_size);

        if offset + nlist_size > data.len() {
            continue;
        }

        let sym_data = &data[offset..offset + nlist_size];

        // Parse nlist entry
        let n_strx = read_u32(sym_data, 0, is_little_endian)?;
        let n_type = sym_data[4];

        // Check if this is an external symbol
        if (n_type & N_EXT) == 0 {
            continue;
        }

        // Get symbol name
        if n_strx as usize >= string_table.len() {
            continue;
        }

        let symbol_name = read_cstring(string_table, n_strx as usize)?;
        exports.push(symbol_name);
    }

    Ok(exports)
}

/// Parse export trie for exported symbols (LC_DYLD_INFO)
pub fn parse_export_trie(data: &[u8], export_off: u32, export_size: u32) -> Result<Vec<String>> {
    let mut exports = Vec::new();

    if export_size == 0 {
        return Ok(exports);
    }

    let export_start = export_off as usize;
    let export_end = export_start + export_size as usize;

    if export_end > data.len() {
        return Err(Error::InvalidOffset(export_start));
    }

    let export_data = &data[export_start..export_end];

    // Stack for traversing the trie: (offset, prefix)
    let mut stack = vec![(0, String::new())];
    let mut visited = std::collections::HashSet::new();

    while let Some((offset, prefix)) = stack.pop() {
        // Prevent infinite loops
        if visited.contains(&offset) || offset >= export_data.len() {
            continue;
        }
        visited.insert(offset);

        // Read terminal size (ULEB128)
        let (terminal_size, consumed) = read_uleb128(export_data, offset)?;
        let mut current_offset = offset + consumed;

        // If terminal size > 0, this node exports a symbol
        if terminal_size > 0 {
            if !prefix.is_empty() && prefix != "__mh_execute_header" {
                exports.push(prefix.clone());
            }
            current_offset += terminal_size;
        }

        // Read number of child edges
        if current_offset >= export_data.len() {
            continue;
        }

        let num_edges = export_data[current_offset];
        current_offset += 1;

        // Process each child edge
        for _ in 0..num_edges {
            if current_offset >= export_data.len() {
                break;
            }

            // Read edge label (null-terminated string)
            let label_start = current_offset;
            while current_offset < export_data.len() && export_data[current_offset] != 0 {
                current_offset += 1;
            }

            if current_offset >= export_data.len() {
                break;
            }

            // Extract label
            let label =
                String::from_utf8_lossy(&export_data[label_start..current_offset]).to_string();
            current_offset += 1; // Skip null terminator

            // Read child node offset (ULEB128)
            if current_offset >= export_data.len() {
                break;
            }

            let (child_offset, consumed) = read_uleb128(export_data, current_offset)?;
            current_offset += consumed;

            // Add child to stack
            let new_prefix = format!("{}{}", prefix, label);
            stack.push((child_offset, new_prefix));
        }
    }

    Ok(exports)
}

/// Read ULEB128 encoded integer
pub fn read_uleb128(data: &[u8], offset: usize) -> Result<(usize, usize)> {
    let mut value = 0usize;
    let mut shift = 0;
    let mut consumed = 0;

    while offset + consumed < data.len() {
        let byte = data[offset + consumed];
        consumed += 1;

        value |= ((byte & 0x7F) as usize) << shift;

        // Check if this is the last byte (MSB is 0)
        if byte & 0x80 == 0 {
            return Ok((value, consumed));
        }

        shift += 7;

        // Prevent overflow
        if shift > 63 {
            return Err(Error::ParseError("ULEB128 overflow".to_string()));
        }
    }

    Err(Error::ParseError("Incomplete ULEB128".to_string()))
}

/// Read u16 with endianness
pub fn read_u16(data: &[u8], offset: usize, is_little_endian: bool) -> Result<u16> {
    if offset + 2 > data.len() {
        return Err(Error::InvalidOffset(offset));
    }

    let bytes = &data[offset..offset + 2];
    Ok(if is_little_endian {
        LittleEndian::read_u16(bytes)
    } else {
        BigEndian::read_u16(bytes)
    })
}

/// Calculate similarity hashes for the binary
pub fn calculate_similarity_hashes(
    imports: &[ImportedSymbol],
    exports: &[String],
    dylibs: &[DylibInfo],
    entitlements: &[String],
) -> SimilarityHashes {
    use md5::Md5;
    use sha2::Digest;

    // Dylib hash - hash of sorted dylib names
    let dylib_hash = {
        let mut dylib_names: Vec<String> = dylibs.iter().map(|d| d.name.clone()).collect();
        dylib_names.sort();
        let joined = dylib_names.join(",");
        let mut hasher = Md5::new();
        hasher.update(joined.as_bytes());
        hex::encode(hasher.finalize())
    };

    // Import hash - hash of sorted imported function names
    let import_hash = {
        let mut all_imports = Vec::new();
        for import in imports {
            all_imports.extend(import.symbols.clone());
        }
        all_imports.sort();
        all_imports.dedup();
        let joined = all_imports.join(",");
        let mut hasher = Md5::new();
        hasher.update(joined.as_bytes());
        hex::encode(hasher.finalize())
    };

    // Export hash - hash of sorted exported symbols
    let export_hash = {
        let mut sorted_exports = exports.to_vec();
        sorted_exports.sort();
        let joined = sorted_exports.join(",");
        let mut hasher = Md5::new();
        hasher.update(joined.as_bytes());
        hex::encode(hasher.finalize())
    };

    // Symhash - combined hash of imports and exports
    let symhash = {
        let mut all_symbols = Vec::new();
        for import in imports {
            all_symbols.extend(import.symbols.clone());
        }
        all_symbols.extend(exports.iter().cloned());
        all_symbols.sort();
        all_symbols.dedup();
        let joined = all_symbols.join(",");
        let mut hasher = Md5::new();
        hasher.update(joined.as_bytes());
        hex::encode(hasher.finalize())
    };

    // Entitlement hash
    let entitlement_hash = if !entitlements.is_empty() {
        let mut sorted_ents = entitlements.to_vec();
        sorted_ents.sort();
        let joined = sorted_ents.join(",");
        let mut hasher = Md5::new();
        hasher.update(joined.as_bytes());
        Some(hex::encode(hasher.finalize()))
    } else {
        None
    };

    SimilarityHashes {
        dylib_hash,
        export_hash,
        import_hash,
        symhash,
        entitlement_hash,
    }
}
