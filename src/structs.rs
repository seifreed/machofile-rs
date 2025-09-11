//! Mach-O file format structures

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachHeader32 {
    pub magic: u32,
    pub cputype: i32,
    pub cpusubtype: i32,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachHeader64 {
    pub magic: u32,
    pub cputype: i32,
    pub cpusubtype: i32,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
    pub reserved: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MachHeader {
    MachO32(MachHeader32),
    MachO64(MachHeader64),
}

impl MachHeader {
    pub fn magic(&self) -> u32 {
        match self {
            MachHeader::MachO32(h) => h.magic,
            MachHeader::MachO64(h) => h.magic,
        }
    }

    pub fn cputype(&self) -> i32 {
        match self {
            MachHeader::MachO32(h) => h.cputype,
            MachHeader::MachO64(h) => h.cputype,
        }
    }

    pub fn cpusubtype(&self) -> i32 {
        match self {
            MachHeader::MachO32(h) => h.cpusubtype,
            MachHeader::MachO64(h) => h.cpusubtype,
        }
    }

    pub fn filetype(&self) -> u32 {
        match self {
            MachHeader::MachO32(h) => h.filetype,
            MachHeader::MachO64(h) => h.filetype,
        }
    }

    pub fn ncmds(&self) -> u32 {
        match self {
            MachHeader::MachO32(h) => h.ncmds,
            MachHeader::MachO64(h) => h.ncmds,
        }
    }

    pub fn sizeofcmds(&self) -> u32 {
        match self {
            MachHeader::MachO32(h) => h.sizeofcmds,
            MachHeader::MachO64(h) => h.sizeofcmds,
        }
    }

    pub fn flags(&self) -> u32 {
        match self {
            MachHeader::MachO32(h) => h.flags,
            MachHeader::MachO64(h) => h.flags,
        }
    }

    pub fn is_64_bit(&self) -> bool {
        matches!(self, MachHeader::MachO64(_))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FatHeader {
    pub magic: u32,
    pub nfat_arch: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FatArch {
    pub cputype: i32,
    pub cpusubtype: i32,
    pub offset: u32,
    pub size: u32,
    pub align: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FatArch64 {
    pub cputype: i32,
    pub cpusubtype: i32,
    pub offset: u64,
    pub size: u64,
    pub align: u32,
    pub reserved: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadCommand {
    pub cmd: u32,
    pub cmdsize: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentCommand32 {
    pub cmd: u32,
    pub cmdsize: u32,
    pub segname: [u8; 16],
    pub vmaddr: u32,
    pub vmsize: u32,
    pub fileoff: u32,
    pub filesize: u32,
    pub maxprot: u32,
    pub initprot: u32,
    pub nsects: u32,
    pub flags: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentCommand64 {
    pub cmd: u32,
    pub cmdsize: u32,
    pub segname: [u8; 16],
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: u32,
    pub initprot: u32,
    pub nsects: u32,
    pub flags: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section32 {
    pub sectname: [u8; 16],
    pub segname: [u8; 16],
    pub addr: u32,
    pub size: u32,
    pub offset: u32,
    pub align: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub flags: u32,
    pub reserved1: u32,
    pub reserved2: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section64 {
    pub sectname: [u8; 16],
    pub segname: [u8; 16],
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub align: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub flags: u32,
    pub reserved1: u32,
    pub reserved2: u32,
    pub reserved3: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DylibCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub dylib: Dylib,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dylib {
    pub name: u32, // offset to name string
    pub timestamp: u32,
    pub current_version: u32,
    pub compatibility_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymtabCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub symoff: u32,
    pub nsyms: u32,
    pub stroff: u32,
    pub strsize: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DysymtabCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub ilocalsym: u32,
    pub nlocalsym: u32,
    pub iextdefsym: u32,
    pub nextdefsym: u32,
    pub iundefsym: u32,
    pub nundefsym: u32,
    pub tocoff: u32,
    pub ntoc: u32,
    pub modtaboff: u32,
    pub nmodtab: u32,
    pub extrefsymoff: u32,
    pub nextrefsyms: u32,
    pub indirectsymoff: u32,
    pub nindirectsyms: u32,
    pub extreloff: u32,
    pub nextrel: u32,
    pub locreloff: u32,
    pub nlocrel: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UuidCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub uuid: [u8; 16],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DyldInfoCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub rebase_off: u32,
    pub rebase_size: u32,
    pub bind_off: u32,
    pub bind_size: u32,
    pub weak_bind_off: u32,
    pub weak_bind_size: u32,
    pub lazy_bind_off: u32,
    pub lazy_bind_size: u32,
    pub export_off: u32,
    pub export_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkeditDataCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub dataoff: u32,
    pub datasize: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MainCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub entryoff: u64,
    pub stacksize: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionMinCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub version: u32,
    pub sdk: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildVersionCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub platform: u32,
    pub minos: u32,
    pub sdk: u32,
    pub ntools: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceVersionCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionInfoCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub cryptoff: u32,
    pub cryptsize: u32,
    pub cryptid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionInfoCommand64 {
    pub cmd: u32,
    pub cmdsize: u32,
    pub cryptoff: u32,
    pub cryptsize: u32,
    pub cryptid: u32,
    pub pad: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpathCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub path: u32, // offset to path string
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkerOptionCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub thread_state: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutinesCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub init_address: u32,
    pub init_module: u32,
    pub reserved1: u32,
    pub reserved2: u32,
    pub reserved3: u32,
    pub reserved4: u32,
    pub reserved5: u32,
    pub reserved6: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutinesCommand64 {
    pub cmd: u32,
    pub cmdsize: u32,
    pub init_address: u64,
    pub init_module: u64,
    pub reserved1: u64,
    pub reserved2: u64,
    pub reserved3: u64,
    pub reserved4: u64,
    pub reserved5: u64,
    pub reserved6: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubFrameworkCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub umbrella: u32, // offset to umbrella string
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubClientCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub client: u32, // offset to client string
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubLibraryCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub sub_library: u32, // offset to sub_library string
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubUmbrellaCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub sub_umbrella: u32, // offset to sub_umbrella string
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreboundDylibCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub name: u32, // offset to library name
    pub nmodules: u32,
    pub linked_modules: u32, // offset to linked modules
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DylinkerCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub name: u32, // offset to name string
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoLevelHintsCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub offset: u32,
    pub nhints: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrebindCksumCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub cksum: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesetEntryCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub vmaddr: u64,
    pub fileoff: u64,
    pub entry_id: u32, // offset to entry id string
    pub reserved: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub data_owner: [u8; 16],
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Nlist32 {
    pub n_strx: u32,
    pub n_type: u8,
    pub n_sect: u8,
    pub n_desc: u16,
    pub n_value: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Nlist64 {
    pub n_strx: u32,
    pub n_type: u8,
    pub n_sect: u8,
    pub n_desc: u16,
    pub n_value: u64,
}

// Code signature structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeSignature {
    pub signed: bool,
    pub signing_status: String,
    pub certificates: Vec<Certificate>,
    pub entitlements: Vec<String>,
    pub code_directory: Option<CodeDirectory>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub index: usize,
    pub size: usize,
    pub subject: String,
    pub issuer: String,
    pub is_apple_cert: bool,
    pub cert_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeDirectory {
    pub version: u32,
    pub flags: u32,
    pub hash_offset: u32,
    pub identifier_offset: u32,
    pub special_slots: u32,
    pub code_slots: u32,
    pub hash_size: u32,
    pub hash_type: u32,
    pub hash_algorithm: String,
    pub identifier: String,
    pub signing_flags: Vec<String>,
}

// Parsed data structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Segment {
    pub name: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: u32,
    pub initprot: u32,
    pub nsects: u32,
    pub flags: u32,
    pub entropy: f64,
    pub sections: Vec<Section>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    pub segment: String,
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub align: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub flags: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DylibInfo {
    pub name: String,
    pub timestamp: u32,
    pub current_version: u32,
    pub compatibility_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    pub name: String,
    pub n_type: u8,
    pub n_sect: u8,
    pub n_desc: u16,
    pub n_value: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedSymbol {
    pub dylib: String,
    pub symbols: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryPoint {
    pub entry_type: String,
    pub entry_address: u64,
    pub thread_data_size: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub platform: String,
    pub min_version: String,
    pub sdk_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralInfo {
    pub filename: Option<String>,
    pub filesize: usize,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarityHashes {
    pub dylib_hash: String,
    pub export_hash: String,
    pub import_hash: String,
    pub symhash: String,
    pub entitlement_hash: Option<String>,
}
