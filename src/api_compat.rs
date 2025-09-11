//! Python API compatibility layer
//!
//! This module provides getter methods that match the Python API

use crate::structs::*;
use crate::{MachO, UniversalMachO};
use std::collections::HashMap;

impl UniversalMachO {
    /// Get architectures in the universal binary
    pub fn get_architectures(&self) -> Vec<String> {
        self.machos.keys().cloned().collect()
    }

    /// Get MachO for specific architecture
    pub fn get_macho_for_arch(&self, arch: &str) -> Option<&MachO> {
        self.machos.get(arch)
    }

    /// Get general info
    pub fn get_general_info(&self) -> &GeneralInfo {
        &self.general_info
    }

    /// Get Mach-O header for architecture
    pub fn get_macho_header(&self, arch: Option<&str>) -> Option<&MachHeader> {
        if let Some(arch_name) = arch {
            self.machos.get(arch_name).map(|m| &m.header)
        } else {
            // Return first architecture if no arch specified
            self.machos.values().next().map(|m| &m.header)
        }
    }

    /// Get imported functions
    pub fn get_imported_functions(&self, arch: Option<&str>) -> Vec<ImportedSymbol> {
        if let Some(arch_name) = arch {
            self.machos
                .get(arch_name)
                .map(|m| m.imported_symbols.clone())
                .unwrap_or_default()
        } else {
            // Combine from all architectures
            let mut all_imports = Vec::new();
            for macho in self.machos.values() {
                all_imports.extend(macho.imported_symbols.clone());
            }
            all_imports
        }
    }

    /// Get exported symbols
    pub fn get_exported_symbols(&self, arch: Option<&str>) -> Vec<String> {
        if let Some(arch_name) = arch {
            self.machos
                .get(arch_name)
                .map(|m| m.exported_symbols.clone())
                .unwrap_or_default()
        } else {
            // Combine from all architectures
            let mut all_exports = Vec::new();
            for macho in self.machos.values() {
                all_exports.extend(macho.exported_symbols.clone());
            }
            all_exports.sort();
            all_exports.dedup();
            all_exports
        }
    }

    /// Get similarity hashes
    pub fn get_similarity_hashes(&self, arch: Option<&str>) -> Option<SimilarityHashes> {
        if let Some(arch_name) = arch {
            self.machos
                .get(arch_name)
                .and_then(|m| m.similarity_hashes.clone())
        } else {
            // Combine hashes from all architectures
            self.get_combined_similarity_hashes()
        }
    }

    fn get_combined_similarity_hashes(&self) -> Option<SimilarityHashes> {
        use md5::{Digest, Md5};

        let mut all_dylibs = Vec::new();
        let mut all_imports = Vec::new();
        let mut all_exports = Vec::new();
        let mut all_entitlements = Vec::new();

        for macho in self.machos.values() {
            all_dylibs.extend(macho.dylibs.iter().map(|d| d.name.clone()));

            for import in &macho.imported_symbols {
                all_imports.extend(import.symbols.clone());
            }

            all_exports.extend(macho.exported_symbols.clone());

            if let Some(ref cs) = macho.code_signature {
                all_entitlements.extend(cs.entitlements.clone());
            }
        }

        // Sort and deduplicate
        all_dylibs.sort();
        all_dylibs.dedup();
        all_imports.sort();
        all_imports.dedup();
        all_exports.sort();
        all_exports.dedup();
        all_entitlements.sort();
        all_entitlements.dedup();

        // Calculate hashes
        let dylib_hash = {
            let mut hasher = Md5::new();
            hasher.update(all_dylibs.join(",").as_bytes());
            hex::encode(hasher.finalize())
        };

        let import_hash = {
            let mut hasher = Md5::new();
            hasher.update(all_imports.join(",").as_bytes());
            hex::encode(hasher.finalize())
        };

        let export_hash = {
            let mut hasher = Md5::new();
            hasher.update(all_exports.join(",").as_bytes());
            hex::encode(hasher.finalize())
        };

        let symhash = {
            let mut all_symbols = all_imports.clone();
            all_symbols.extend(all_exports);
            all_symbols.sort();
            all_symbols.dedup();
            let mut hasher = Md5::new();
            hasher.update(all_symbols.join(",").as_bytes());
            hex::encode(hasher.finalize())
        };

        let entitlement_hash = if !all_entitlements.is_empty() {
            let mut hasher = Md5::new();
            hasher.update(all_entitlements.join(",").as_bytes());
            Some(hex::encode(hasher.finalize()))
        } else {
            None
        };

        Some(SimilarityHashes {
            dylib_hash,
            export_hash,
            import_hash,
            symhash,
            entitlement_hash,
        })
    }

    /// Get dylib hash
    pub fn get_dylib_hash(&self, arch: Option<&str>) -> Option<String> {
        self.get_similarity_hashes(arch).map(|h| h.dylib_hash)
    }

    /// Get import hash
    pub fn get_import_hash(&self, arch: Option<&str>) -> Option<String> {
        self.get_similarity_hashes(arch).map(|h| h.import_hash)
    }

    /// Get export hash
    pub fn get_export_hash(&self, arch: Option<&str>) -> Option<String> {
        self.get_similarity_hashes(arch).map(|h| h.export_hash)
    }

    /// Get entitlement hash
    pub fn get_entitlement_hash(&self, arch: Option<&str>) -> Option<String> {
        self.get_similarity_hashes(arch)
            .and_then(|h| h.entitlement_hash)
    }

    /// Get symhash
    pub fn get_symhash(&self, arch: Option<&str>) -> Option<String> {
        self.get_similarity_hashes(arch).map(|h| h.symhash)
    }

    /// Get load commands
    pub fn get_load_commands(&self, arch: Option<&str>) -> Vec<HashMap<String, String>> {
        use crate::constants::get_load_command_name;

        let machos_to_process: Vec<&MachO> = if let Some(arch_name) = arch {
            self.machos.get(arch_name).into_iter().collect()
        } else {
            self.machos.values().collect()
        };

        let mut result = Vec::new();
        for macho in machos_to_process {
            for cmd in &macho.load_commands {
                let mut cmd_info = HashMap::new();

                let (cmd_type, cmd_size) = match cmd {
                    crate::LoadCommandData::Segment32(s) => (s.cmd, s.cmdsize),
                    crate::LoadCommandData::Segment64(s) => (s.cmd, s.cmdsize),
                    crate::LoadCommandData::Dylib(d, _) => (d.cmd, d.cmdsize),
                    crate::LoadCommandData::Symtab(s) => (s.cmd, s.cmdsize),
                    crate::LoadCommandData::Dysymtab(d) => (d.cmd, d.cmdsize),
                    crate::LoadCommandData::Uuid(u) => (u.cmd, u.cmdsize),
                    crate::LoadCommandData::Main(m) => (m.cmd, m.cmdsize),
                    crate::LoadCommandData::Other(o) => (o.cmd, o.cmdsize),
                    _ => (0, 0),
                };

                cmd_info.insert(
                    "cmd".to_string(),
                    get_load_command_name(cmd_type).to_string(),
                );
                cmd_info.insert("cmdsize".to_string(), cmd_size.to_string());

                result.push(cmd_info);
            }
        }

        result
    }

    /// Get segments
    pub fn get_segments(&self, arch: Option<&str>) -> Vec<&Segment> {
        if let Some(arch_name) = arch {
            self.machos
                .get(arch_name)
                .map(|m| m.segments.iter().collect())
                .unwrap_or_default()
        } else {
            let mut all_segments = Vec::new();
            for macho in self.machos.values() {
                all_segments.extend(macho.segments.iter());
            }
            all_segments
        }
    }

    /// Get dylib commands
    pub fn get_dylib_commands(&self, arch: Option<&str>) -> Vec<&DylibInfo> {
        if let Some(arch_name) = arch {
            self.machos
                .get(arch_name)
                .map(|m| m.dylibs.iter().collect())
                .unwrap_or_default()
        } else {
            let mut all_dylibs = Vec::new();
            for macho in self.machos.values() {
                all_dylibs.extend(macho.dylibs.iter());
            }
            all_dylibs
        }
    }

    /// Get dylib names
    pub fn get_dylib_names(&self, arch: Option<&str>) -> Vec<String> {
        self.get_dylib_commands(arch)
            .into_iter()
            .map(|d| d.name.clone())
            .collect()
    }

    /// Get UUID
    pub fn get_uuid(&self, arch: Option<&str>) -> Option<String> {
        if let Some(arch_name) = arch {
            self.machos.get(arch_name).and_then(|m| m.uuid.clone())
        } else {
            // Return first UUID found
            self.machos.values().find_map(|m| m.uuid.clone())
        }
    }

    /// Get entry point
    pub fn get_entry_point(&self, arch: Option<&str>) -> Option<&EntryPoint> {
        if let Some(arch_name) = arch {
            self.machos
                .get(arch_name)
                .and_then(|m| m.entry_point.as_ref())
        } else {
            // Return first entry point found
            self.machos.values().find_map(|m| m.entry_point.as_ref())
        }
    }

    /// Get version info
    pub fn get_version_info(&self, arch: Option<&str>) -> Option<&VersionInfo> {
        if let Some(arch_name) = arch {
            self.machos
                .get(arch_name)
                .and_then(|m| m.version_info.as_ref())
        } else {
            // Return first version info found
            self.machos.values().find_map(|m| m.version_info.as_ref())
        }
    }

    /// Get code signature info
    pub fn get_code_signature_info(&self, arch: Option<&str>) -> Option<&CodeSignature> {
        if let Some(arch_name) = arch {
            self.machos
                .get(arch_name)
                .and_then(|m| m.code_signature.as_ref())
        } else {
            // Return first code signature found
            self.machos.values().find_map(|m| m.code_signature.as_ref())
        }
    }
}

impl MachO {
    /// Get general info (delegated to parent UniversalMachO)
    pub fn get_general_info(&self) -> GeneralInfo {
        GeneralInfo {
            filename: None,
            filesize: self.data.len(),
            md5: crate::utils::calculate_md5(&self.data),
            sha1: crate::utils::calculate_sha1(&self.data),
            sha256: crate::utils::calculate_sha256(&self.data),
        }
    }

    /// Get Mach-O header
    pub fn get_macho_header(&self) -> &MachHeader {
        &self.header
    }

    /// Get imported functions
    pub fn get_imported_functions(&self) -> &Vec<ImportedSymbol> {
        &self.imported_symbols
    }

    /// Get exported symbols
    pub fn get_exported_symbols(&self) -> &Vec<String> {
        &self.exported_symbols
    }

    /// Get similarity hashes
    pub fn get_similarity_hashes(&self) -> Option<&SimilarityHashes> {
        self.similarity_hashes.as_ref()
    }

    /// Get segments
    pub fn get_segments(&self) -> &Vec<Segment> {
        &self.segments
    }

    /// Get dylib commands
    pub fn get_dylib_commands(&self) -> &Vec<DylibInfo> {
        &self.dylibs
    }

    /// Get dylib names
    pub fn get_dylib_names(&self) -> Vec<String> {
        self.dylibs.iter().map(|d| d.name.clone()).collect()
    }

    /// Get UUID
    pub fn get_uuid(&self) -> Option<&String> {
        self.uuid.as_ref()
    }

    /// Get entry point
    pub fn get_entry_point(&self) -> Option<&EntryPoint> {
        self.entry_point.as_ref()
    }

    /// Get version info
    pub fn get_version_info(&self) -> Option<&VersionInfo> {
        self.version_info.as_ref()
    }

    /// Get code signature info
    pub fn get_code_signature_info(&self) -> Option<&CodeSignature> {
        self.code_signature.as_ref()
    }
}
