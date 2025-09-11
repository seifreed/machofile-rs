//! Mach-O file format constants

// Mach-O magic numbers
pub const MH_MAGIC: u32 = 0xFEEDFACE; // Big endian, 32 bit Mach-O
pub const MH_CIGAM: u32 = 0xCEFAEDFE; // Little endian, 32 bit Mach-O
pub const MH_MAGIC_64: u32 = 0xFEEDFACF; // Big endian, 64 bit Mach-O
pub const MH_CIGAM_64: u32 = 0xCFFAEDFE; // Little endian, 64 bit Mach-O

// Universal binary magic numbers
pub const FAT_MAGIC: u32 = 0xCAFEBABE;
pub const FAT_CIGAM: u32 = 0xBEBAFECA;
pub const FAT_MAGIC_64: u32 = 0xCAFEBABF;
pub const FAT_CIGAM_64: u32 = 0xBFBAFECA;

// CPU architecture masks
pub const CPU_ARCH_MASK: u32 = 0xFF000000;
pub const CPU_ARCH_ABI64: u32 = 0x01000000;
pub const CPU_SUBTYPE_LIB64: u32 = 0x80000000;

// CPU types
pub const CPU_TYPE_X86: u32 = 0x7;
pub const CPU_TYPE_I386: u32 = CPU_TYPE_X86; // Same as X86
pub const CPU_TYPE_X86_64: u32 = 0x1000007;
pub const CPU_TYPE_ARM: u32 = 0xC;
pub const CPU_TYPE_ARM64: u32 = 0x100000C;
pub const CPU_TYPE_PPC: u32 = 0x12;
pub const CPU_TYPE_PPC64: u32 = 0x10000012;
pub const CPU_TYPE_SPARC: u32 = 0x14;
pub const CPU_TYPE_I860: u32 = 0x15;
pub const CPU_TYPE_MC680X0: u32 = 0x6;
pub const CPU_TYPE_MC98000: u32 = 0xA;
pub const CPU_TYPE_HPPA: u32 = 0xB;
pub const CPU_TYPE_MC88000: u32 = 0xD;
pub const CPU_TYPE_ALPHA: u32 = 0x10;

// CPU subtypes
pub const CPU_SUBTYPE_X86_ALL: u32 = 0x3;
pub const CPU_SUBTYPE_X86_64_ALL: u32 = 0x3;
pub const CPU_SUBTYPE_ARM_ALL: u32 = 0x0;
pub const CPU_SUBTYPE_ARM64_ALL: u32 = 0x0;
pub const CPU_SUBTYPE_ARM64_V8: u32 = 0x1;
pub const CPU_SUBTYPE_ARM64E: u32 = 0x2;
pub const CPU_SUBTYPE_ARM64E_WITH_PTRAUTH: u32 = 0x80000002;

// File types
pub const MH_OBJECT: u32 = 0x1;
pub const MH_EXECUTE: u32 = 0x2;
pub const MH_FVMLIB: u32 = 0x3;
pub const MH_CORE: u32 = 0x4;
pub const MH_PRELOAD: u32 = 0x5;
pub const MH_DYLIB: u32 = 0x6;
pub const MH_DYLINKER: u32 = 0x7;
pub const MH_BUNDLE: u32 = 0x8;
pub const MH_DYLIB_STUB: u32 = 0x9;
pub const MH_DSYM: u32 = 0xA;
pub const MH_KEXT_BUNDLE: u32 = 0xB;

// Header flags
pub const MH_NOUNDEFS: u32 = 0x1;
pub const MH_INCRLINK: u32 = 0x2;
pub const MH_DYLDLINK: u32 = 0x4;
pub const MH_BINDATLOAD: u32 = 0x8;
pub const MH_PREBOUND: u32 = 0x10;
pub const MH_SPLIT_SEGS: u32 = 0x20;
pub const MH_LAZY_INIT: u32 = 0x40;
pub const MH_TWOLEVEL: u32 = 0x80;
pub const MH_FORCE_FLAT: u32 = 0x100;
pub const MH_NOMULTIDEFS: u32 = 0x200;
pub const MH_NOFIXPREBINDING: u32 = 0x400;
pub const MH_PREBINDABLE: u32 = 0x800;
pub const MH_ALLMODSBOUND: u32 = 0x1000;
pub const MH_SUBSECTIONS_VIA_SYMBOLS: u32 = 0x2000;
pub const MH_CANONICAL: u32 = 0x4000;
pub const MH_WEAK_DEFINES: u32 = 0x8000;
pub const MH_BINDS_TO_WEAK: u32 = 0x10000;
pub const MH_ALLOW_STACK_EXECUTION: u32 = 0x20000;
pub const MH_ROOT_SAFE: u32 = 0x40000;
pub const MH_SETUID_SAFE: u32 = 0x80000;
pub const MH_NO_REEXPORTED_DYLIBS: u32 = 0x100000;
pub const MH_PIE: u32 = 0x200000;
pub const MH_DEAD_STRIPPABLE_DYLIB: u32 = 0x400000;
pub const MH_HAS_TLV_DESCRIPTORS: u32 = 0x800000;
pub const MH_NO_HEAP_EXECUTION: u32 = 0x1000000;
pub const MH_APP_EXTENSION_SAFE: u32 = 0x2000000;
pub const MH_NLIST_OUTOFSYNC_WITH_DYLDINFO: u32 = 0x4000000;
pub const MH_SIM_SUPPORT: u32 = 0x8000000;
pub const MH_DYLIB_IN_CACHE: u32 = 0x80000000;

// Load command types
pub const LC_REQ_DYLD: u32 = 0x80000000;
pub const LC_SEGMENT: u32 = 0x1;
pub const LC_SYMTAB: u32 = 0x2;
pub const LC_SYMSEG: u32 = 0x3;
pub const LC_THREAD: u32 = 0x4;
pub const LC_UNIXTHREAD: u32 = 0x5;
pub const LC_LOADFVMLIB: u32 = 0x6;
pub const LC_IDFVMLIB: u32 = 0x7;
pub const LC_IDENT: u32 = 0x8;
pub const LC_FVMFILE: u32 = 0x9;
pub const LC_PREPAGE: u32 = 0xA;
pub const LC_DYSYMTAB: u32 = 0xB;
pub const LC_LOAD_DYLIB: u32 = 0xC;
pub const LC_ID_DYLIB: u32 = 0xD;
pub const LC_LOAD_DYLINKER: u32 = 0xE;
pub const LC_ID_DYLINKER: u32 = 0xF;
pub const LC_PREBOUND_DYLIB: u32 = 0x10;
pub const LC_ROUTINES: u32 = 0x11;
pub const LC_SUB_FRAMEWORK: u32 = 0x12;
pub const LC_SUB_UMBRELLA: u32 = 0x13;
pub const LC_SUB_CLIENT: u32 = 0x14;
pub const LC_SUB_LIBRARY: u32 = 0x15;
pub const LC_TWOLEVEL_HINTS: u32 = 0x16;
pub const LC_PREBIND_CKSUM: u32 = 0x17;
pub const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | LC_REQ_DYLD;
pub const LC_SEGMENT_64: u32 = 0x19;
pub const LC_ROUTINES_64: u32 = 0x1A;
pub const LC_UUID: u32 = 0x1B;
pub const LC_RPATH: u32 = 0x1C | LC_REQ_DYLD;
pub const LC_CODE_SIGNATURE: u32 = 0x1D;
pub const LC_SEGMENT_SPLIT_INFO: u32 = 0x1E;
pub const LC_REEXPORT_DYLIB: u32 = 0x1F | LC_REQ_DYLD;
pub const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
pub const LC_ENCRYPTION_INFO: u32 = 0x21;
pub const LC_DYLD_INFO: u32 = 0x22;
pub const LC_DYLD_INFO_ONLY: u32 = LC_DYLD_INFO | LC_REQ_DYLD;
pub const LC_LOAD_UPWARD_DYLIB: u32 = 0x23 | LC_REQ_DYLD;
pub const LC_VERSION_MIN_MACOSX: u32 = 0x24;
pub const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
pub const LC_FUNCTION_STARTS: u32 = 0x26;
pub const LC_DYLD_ENVIRONMENT: u32 = 0x27;
pub const LC_MAIN: u32 = 0x28 | LC_REQ_DYLD;
pub const LC_DATA_IN_CODE: u32 = 0x29;
pub const LC_SOURCE_VERSION: u32 = 0x2A;
pub const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2B;
pub const LC_ENCRYPTION_INFO_64: u32 = 0x2C;
pub const LC_LINKER_OPTION: u32 = 0x2D;
pub const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2E;
pub const LC_VERSION_MIN_TVOS: u32 = 0x2F;
pub const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
pub const LC_NOTE: u32 = 0x31;
pub const LC_BUILD_VERSION: u32 = 0x32;
pub const LC_DYLD_EXPORTS_TRIE: u32 = 0x33 | LC_REQ_DYLD;
pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x34 | LC_REQ_DYLD;
pub const LC_FILESET_ENTRY: u32 = 0x35 | LC_REQ_DYLD;
pub const LC_ATOM_INFO: u32 = 0x36;

// Code signature constants
pub const CSMAGIC_REQUIREMENT: u32 = 0xFADE0C00;
pub const CSMAGIC_REQUIREMENTS: u32 = 0xFADE0C01;
pub const CSMAGIC_CODEDIRECTORY: u32 = 0xFADE0C02;
pub const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xFADE0CC0;
pub const CSMAGIC_EMBEDDED_SIGNATURE_OLD: u32 = 0xFADE0B02;
pub const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xFADE7171;
pub const CSMAGIC_EMBEDDED_DER_ENTITLEMENTS: u32 = 0xFADE7172;
pub const CSMAGIC_DETACHED_SIGNATURE: u32 = 0xFADE0CC1;
pub const CSMAGIC_BLOBWRAPPER: u32 = 0xFADE0B01;
pub const CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT: u32 = 0xFADE8181;

// Code signature slot types
pub const CSSLOT_CODEDIRECTORY: u32 = 0;
pub const CSSLOT_INFOSLOT: u32 = 1;
pub const CSSLOT_REQUIREMENTS: u32 = 2;
pub const CSSLOT_RESOURCEDIR: u32 = 3;
pub const CSSLOT_APPLICATION: u32 = 4;
pub const CSSLOT_ENTITLEMENTS: u32 = 5;
pub const CSSLOT_DER_ENTITLEMENTS: u32 = 7;
pub const CSSLOT_LAUNCH_CONSTRAINT_SELF: u32 = 8;
pub const CSSLOT_LAUNCH_CONSTRAINT_PARENT: u32 = 9;
pub const CSSLOT_LAUNCH_CONSTRAINT_RESPONSIBLE: u32 = 10;
pub const CSSLOT_LIBRARY_CONSTRAINT: u32 = 11;
pub const CSSLOT_ALTERNATE_CODEDIRECTORIES: u32 = 0x1000;
pub const CSSLOT_ALTERNATE_CODEDIRECTORY_MAX: u32 = 5;
pub const CSSLOT_SIGNATURESLOT: u32 = 0x10000;
pub const CSSLOT_IDENTIFICATIONSLOT: u32 = 0x10001;
pub const CSSLOT_TICKETSLOT: u32 = 0x10002;

// Symbol table constants
pub const N_STAB: u8 = 0xE0;
pub const N_PEXT: u8 = 0x10;
pub const N_TYPE: u8 = 0x0E;
pub const N_EXT: u8 = 0x01;
pub const N_UNDF: u8 = 0x0;
pub const N_ABS: u8 = 0x2;
pub const N_SECT: u8 = 0xE;
pub const N_PBUD: u8 = 0xC;
pub const N_INDR: u8 = 0xA;

// Segment flags
pub const SG_HIGHVM: u32 = 0x1;
pub const SG_FVMLIB: u32 = 0x2;
pub const SG_NORELOC: u32 = 0x4;
pub const SG_PROTECTED_VERSION_1: u32 = 0x8;
pub const SG_READ_ONLY: u32 = 0x10;

// VM protection values
pub const VM_PROT_NONE: u32 = 0x0;
pub const VM_PROT_READ: u32 = 0x1;
pub const VM_PROT_WRITE: u32 = 0x2;
pub const VM_PROT_EXECUTE: u32 = 0x4;

// Helper functions
pub fn get_cpu_type_name(cpu_type: u32) -> &'static str {
    match cpu_type {
        CPU_TYPE_X86 => "x86",
        CPU_TYPE_X86_64 => "x86_64",
        CPU_TYPE_ARM => "ARM",
        CPU_TYPE_ARM64 => "ARM 64-bit",
        CPU_TYPE_PPC => "PowerPC",
        CPU_TYPE_PPC64 => "PowerPC 64-bit",
        CPU_TYPE_SPARC => "SPARC",
        CPU_TYPE_I860 => "Intel i860",
        CPU_TYPE_MC680X0 => "Motorola 68000",
        CPU_TYPE_MC98000 => "Motorola PowerPC",
        CPU_TYPE_HPPA => "HP PA-RISC",
        CPU_TYPE_MC88000 => "Motorola 88000",
        CPU_TYPE_ALPHA => "DEC Alpha",
        _ => "Unknown",
    }
}

pub fn get_cpu_subtype_name(cpu_type: u32, cpu_subtype: u32) -> &'static str {
    let subtype = cpu_subtype & !CPU_SUBTYPE_LIB64;

    match (cpu_type, subtype) {
        (CPU_TYPE_X86, 0x3) | (CPU_TYPE_X86_64, 0x3) => "x86_ALL",
        (CPU_TYPE_X86_64, 0x8) => "x86_64_H",
        (CPU_TYPE_ARM, 0x0) | (CPU_TYPE_ARM64, 0x0) => "ARM_ALL",
        (CPU_TYPE_ARM64, 0x1) => "ARM64_V8",
        (CPU_TYPE_ARM64, 0x2) => "ARM64E",
        (CPU_TYPE_ARM, 0x5) => "ARM_V4T",
        (CPU_TYPE_ARM, 0x6) => "ARM_V6",
        (CPU_TYPE_ARM, 0x7) => "ARM_V5TEJ",
        (CPU_TYPE_ARM, 0x9) => "ARM_V7",
        (CPU_TYPE_ARM, 0xA) => "ARM_V7F",
        (CPU_TYPE_ARM, 0xB) => "ARM_V7S",
        (CPU_TYPE_ARM, 0xC) => "ARM_V7K",
        _ => "Unknown",
    }
}

pub fn get_file_type_name(file_type: u32) -> &'static str {
    match file_type {
        MH_OBJECT => "OBJECT",
        MH_EXECUTE => "EXECUTE",
        MH_FVMLIB => "FVMLIB",
        MH_CORE => "CORE",
        MH_PRELOAD => "PRELOAD",
        MH_DYLIB => "DYLIB",
        MH_DYLINKER => "DYLINKER",
        MH_BUNDLE => "BUNDLE",
        MH_DYLIB_STUB => "DYLIB_STUB",
        MH_DSYM => "DSYM",
        MH_KEXT_BUNDLE => "KEXT_BUNDLE",
        _ => "Unknown",
    }
}

pub fn get_load_command_name(cmd: u32) -> &'static str {
    match cmd & !LC_REQ_DYLD {
        LC_SEGMENT => "LC_SEGMENT",
        LC_SYMTAB => "LC_SYMTAB",
        LC_SYMSEG => "LC_SYMSEG",
        LC_THREAD => "LC_THREAD",
        LC_UNIXTHREAD => "LC_UNIXTHREAD",
        LC_LOADFVMLIB => "LC_LOADFVMLIB",
        LC_IDFVMLIB => "LC_IDFVMLIB",
        LC_IDENT => "LC_IDENT",
        LC_FVMFILE => "LC_FVMFILE",
        LC_PREPAGE => "LC_PREPAGE",
        LC_DYSYMTAB => "LC_DYSYMTAB",
        LC_LOAD_DYLIB => "LC_LOAD_DYLIB",
        LC_ID_DYLIB => "LC_ID_DYLIB",
        LC_LOAD_DYLINKER => "LC_LOAD_DYLINKER",
        LC_ID_DYLINKER => "LC_ID_DYLINKER",
        LC_PREBOUND_DYLIB => "LC_PREBOUND_DYLIB",
        LC_ROUTINES => "LC_ROUTINES",
        LC_SUB_FRAMEWORK => "LC_SUB_FRAMEWORK",
        LC_SUB_UMBRELLA => "LC_SUB_UMBRELLA",
        LC_SUB_CLIENT => "LC_SUB_CLIENT",
        LC_SUB_LIBRARY => "LC_SUB_LIBRARY",
        LC_TWOLEVEL_HINTS => "LC_TWOLEVEL_HINTS",
        LC_PREBIND_CKSUM => "LC_PREBIND_CKSUM",
        0x18 => "LC_LOAD_WEAK_DYLIB",
        LC_SEGMENT_64 => "LC_SEGMENT_64",
        LC_ROUTINES_64 => "LC_ROUTINES_64",
        LC_UUID => "LC_UUID",
        0x1C => "LC_RPATH",
        LC_CODE_SIGNATURE => "LC_CODE_SIGNATURE",
        LC_SEGMENT_SPLIT_INFO => "LC_SEGMENT_SPLIT_INFO",
        0x1F => "LC_REEXPORT_DYLIB",
        LC_LAZY_LOAD_DYLIB => "LC_LAZY_LOAD_DYLIB",
        LC_ENCRYPTION_INFO => "LC_ENCRYPTION_INFO",
        LC_DYLD_INFO => "LC_DYLD_INFO",
        LC_DYLD_INFO_ONLY => "LC_DYLD_INFO_ONLY",
        0x23 => "LC_LOAD_UPWARD_DYLIB",
        LC_VERSION_MIN_MACOSX => "LC_VERSION_MIN_MACOSX",
        LC_VERSION_MIN_IPHONEOS => "LC_VERSION_MIN_IPHONEOS",
        LC_FUNCTION_STARTS => "LC_FUNCTION_STARTS",
        LC_DYLD_ENVIRONMENT => "LC_DYLD_ENVIRONMENT",
        0x28 => "LC_MAIN",
        LC_DATA_IN_CODE => "LC_DATA_IN_CODE",
        LC_SOURCE_VERSION => "LC_SOURCE_VERSION",
        LC_DYLIB_CODE_SIGN_DRS => "LC_DYLIB_CODE_SIGN_DRS",
        LC_ENCRYPTION_INFO_64 => "LC_ENCRYPTION_INFO_64",
        LC_LINKER_OPTION => "LC_LINKER_OPTION",
        LC_LINKER_OPTIMIZATION_HINT => "LC_LINKER_OPTIMIZATION_HINT",
        LC_VERSION_MIN_TVOS => "LC_VERSION_MIN_TVOS",
        LC_VERSION_MIN_WATCHOS => "LC_VERSION_MIN_WATCHOS",
        LC_NOTE => "LC_NOTE",
        LC_BUILD_VERSION => "LC_BUILD_VERSION",
        0x33 => "LC_DYLD_EXPORTS_TRIE",
        0x34 => "LC_DYLD_CHAINED_FIXUPS",
        0x35 => "LC_FILESET_ENTRY",
        LC_ATOM_INFO => "LC_ATOM_INFO",
        _ => "Unknown",
    }
}

pub fn get_header_flags(flags: u32) -> Vec<&'static str> {
    let mut result = Vec::new();

    if flags & MH_NOUNDEFS != 0 {
        result.push("NOUNDEFS");
    }
    if flags & MH_INCRLINK != 0 {
        result.push("INCRLINK");
    }
    if flags & MH_DYLDLINK != 0 {
        result.push("DYLDLINK");
    }
    if flags & MH_BINDATLOAD != 0 {
        result.push("BINDATLOAD");
    }
    if flags & MH_PREBOUND != 0 {
        result.push("PREBOUND");
    }
    if flags & MH_SPLIT_SEGS != 0 {
        result.push("SPLIT_SEGS");
    }
    if flags & MH_LAZY_INIT != 0 {
        result.push("LAZY_INIT");
    }
    if flags & MH_TWOLEVEL != 0 {
        result.push("TWOLEVEL");
    }
    if flags & MH_FORCE_FLAT != 0 {
        result.push("FORCE_FLAT");
    }
    if flags & MH_NOMULTIDEFS != 0 {
        result.push("NOMULTIDEFS");
    }
    if flags & MH_NOFIXPREBINDING != 0 {
        result.push("NOFIXPREBINDING");
    }
    if flags & MH_PREBINDABLE != 0 {
        result.push("PREBINDABLE");
    }
    if flags & MH_ALLMODSBOUND != 0 {
        result.push("ALLMODSBOUND");
    }
    if flags & MH_SUBSECTIONS_VIA_SYMBOLS != 0 {
        result.push("SUBSECTIONS_VIA_SYMBOLS");
    }
    if flags & MH_CANONICAL != 0 {
        result.push("CANONICAL");
    }
    if flags & MH_WEAK_DEFINES != 0 {
        result.push("WEAK_DEFINES");
    }
    if flags & MH_BINDS_TO_WEAK != 0 {
        result.push("BINDS_TO_WEAK");
    }
    if flags & MH_ALLOW_STACK_EXECUTION != 0 {
        result.push("ALLOW_STACK_EXECUTION");
    }
    if flags & MH_ROOT_SAFE != 0 {
        result.push("ROOT_SAFE");
    }
    if flags & MH_SETUID_SAFE != 0 {
        result.push("SETUID_SAFE");
    }
    if flags & MH_NO_REEXPORTED_DYLIBS != 0 {
        result.push("NO_REEXPORTED_DYLIBS");
    }
    if flags & MH_PIE != 0 {
        result.push("PIE");
    }
    if flags & MH_DEAD_STRIPPABLE_DYLIB != 0 {
        result.push("DEAD_STRIPPABLE_DYLIB");
    }
    if flags & MH_HAS_TLV_DESCRIPTORS != 0 {
        result.push("HAS_TLV_DESCRIPTORS");
    }
    if flags & MH_NO_HEAP_EXECUTION != 0 {
        result.push("NO_HEAP_EXECUTION");
    }
    if flags & MH_APP_EXTENSION_SAFE != 0 {
        result.push("APP_EXTENSION_SAFE");
    }
    if flags & MH_NLIST_OUTOFSYNC_WITH_DYLDINFO != 0 {
        result.push("NLIST_OUTOFSYNC_WITH_DYLDINFO");
    }
    if flags & MH_SIM_SUPPORT != 0 {
        result.push("SIM_SUPPORT");
    }
    if flags & MH_DYLIB_IN_CACHE != 0 {
        result.push("DYLIB_IN_CACHE");
    }

    result
}
