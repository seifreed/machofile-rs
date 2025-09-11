use clap::Parser;
use machofile::constants::*;
use machofile::structs::*;
use machofile::{parse_file, LoadCommandData, MachO, UniversalMachO};
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(name = "machofile")]
#[command(author = "Marc Rivero <mriverolopez@gmail.com>")]
#[command(version = "2025.08.05")]
#[command(about = "Parse Mach-O binary structures")]
struct Cli {
    /// Path to the file to be parsed
    #[arg(short = 'f', long = "file", required = true)]
    file: PathBuf,

    /// Output data in JSON format
    #[arg(short = 'j', long = "json")]
    json: bool,

    /// Output raw values in JSON format (use with -j/--json)
    #[arg(long = "raw")]
    raw: bool,

    /// Print all info about the file
    #[arg(short = 'a', long = "all")]
    all: bool,

    /// Print Dylib Command Table and Dylib list
    #[arg(short = 'd', long = "dylib")]
    dylib: bool,

    /// Print exported symbols
    #[arg(short = 'e', long = "exports")]
    exports: bool,

    /// Print entry point information
    #[arg(long = "ep")]
    entry_point: bool,

    /// Print general info about the file
    #[arg(short = 'g', long = "general_info")]
    general_info: bool,

    /// Print Mach-O header info
    #[arg(long = "header")]
    header: bool,

    /// Print imported symbols
    #[arg(short = 'i', long = "imports")]
    imports: bool,

    /// Print Load Command Table and Command list
    #[arg(short = 'l', long = "load_cmd_t")]
    load_cmd: bool,

    /// Print File Segments info
    #[arg(long = "segments")]
    segments: bool,

    /// Print code signature and entitlements information
    #[arg(long = "signature")]
    signature: bool,

    /// Print similarity hashes
    #[arg(long = "similarity")]
    similarity: bool,

    /// Print UUID
    #[arg(short = 'u', long = "uuid")]
    uuid: bool,

    /// Print version information
    #[arg(short = 'v', long = "version")]
    version: bool,

    /// Show info for specific architecture only (for Universal binaries)
    #[arg(long = "arch")]
    arch: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    let result = parse_file(&cli.file);

    match result {
        Ok(universal) => {
            if cli.json {
                print_json(&universal, &cli);
            } else {
                print_text(&universal, &cli);
            }
        }
        Err(e) => {
            eprintln!("Error parsing file: {}", e);
            process::exit(1);
        }
    }
}

fn print_json(universal: &UniversalMachO, cli: &Cli) {
    let mut output = serde_json::Map::new();

    if cli.all || cli.general_info {
        output.insert(
            "general_info".to_string(),
            serde_json::to_value(&universal.general_info).unwrap(),
        );
    }

    if universal.is_universal {
        output.insert(
            "architectures".to_string(),
            serde_json::to_value(universal.get_architectures()).unwrap(),
        );
    }

    // Filter by architecture if specified
    let machos_to_process: Vec<(&String, &MachO)> = if let Some(ref arch) = cli.arch {
        universal
            .machos
            .iter()
            .filter(|(a, _)| a == &arch)
            .collect()
    } else {
        universal.machos.iter().collect()
    };

    for (arch_name, macho) in machos_to_process {
        let mut arch_output = serde_json::Map::new();

        if cli.all || cli.header {
            let header_info = if cli.raw {
                get_raw_header_info(&macho.header)
            } else {
                get_formatted_header_info(&macho.header)
            };
            arch_output.insert("header".to_string(), header_info);
        }

        if cli.all || cli.segments {
            arch_output.insert(
                "segments".to_string(),
                serde_json::to_value(&macho.segments).unwrap(),
            );
        }

        if cli.all || cli.dylib {
            arch_output.insert(
                "dylibs".to_string(),
                serde_json::to_value(&macho.dylibs).unwrap(),
            );
        }

        if cli.all || cli.imports {
            arch_output.insert(
                "imported_symbols".to_string(),
                serde_json::to_value(&macho.imported_symbols).unwrap(),
            );
        }

        if cli.all || cli.exports {
            arch_output.insert(
                "exported_symbols".to_string(),
                serde_json::to_value(&macho.exported_symbols).unwrap(),
            );
        }

        if cli.all || cli.uuid {
            if let Some(ref uuid) = macho.uuid {
                arch_output.insert("uuid".to_string(), serde_json::Value::String(uuid.clone()));
            }
        }

        if cli.all || cli.entry_point {
            if let Some(ref entry) = macho.entry_point {
                arch_output.insert(
                    "entry_point".to_string(),
                    serde_json::to_value(entry).unwrap(),
                );
            }
        }

        if cli.all || cli.version {
            if let Some(ref version) = macho.version_info {
                arch_output.insert(
                    "version_info".to_string(),
                    serde_json::to_value(version).unwrap(),
                );
            }
        }

        if cli.all || cli.signature {
            if let Some(ref sig) = macho.code_signature {
                arch_output.insert(
                    "code_signature".to_string(),
                    serde_json::to_value(sig).unwrap(),
                );
            }
        }

        if cli.all || cli.similarity {
            if let Some(ref hashes) = macho.similarity_hashes {
                arch_output.insert(
                    "similarity_hashes".to_string(),
                    serde_json::to_value(hashes).unwrap(),
                );
            }
        }

        if universal.is_universal {
            output.insert(arch_name.clone(), serde_json::Value::Object(arch_output));
        } else {
            // For single-arch binaries, put the data at the top level
            for (k, v) in arch_output {
                output.insert(k, v);
            }
        }
    }

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

fn print_text(universal: &UniversalMachO, cli: &Cli) {
    if cli.all || cli.general_info {
        print_general_info(universal);
    }

    // Filter by architecture if specified
    let machos_to_process: Vec<(&String, &MachO)> = if let Some(ref arch) = cli.arch {
        universal
            .machos
            .iter()
            .filter(|(a, _)| a == &arch)
            .collect()
    } else {
        universal.machos.iter().collect()
    };

    for (arch_name, macho) in machos_to_process {
        if universal.is_universal {
            println!("\n[Architecture: {}]", arch_name);
        }

        if cli.all || cli.header {
            print_header(macho);
        }

        if cli.all || cli.load_cmd {
            print_load_commands(macho);
        }

        if cli.all || cli.segments {
            print_segments(macho);
        }

        if cli.all || cli.dylib {
            print_dylibs(macho);
        }

        if cli.all || cli.uuid {
            if let Some(ref uuid) = macho.uuid {
                println!("\n[UUID]\n        {}", uuid);
            }
        }

        if cli.all || cli.entry_point {
            if let Some(ref entry) = macho.entry_point {
                println!("\n[Entry Point]");
                println!("        type:             {}", entry.entry_type);
                println!("        entry_address:    {:#x}", entry.entry_address);
                if let Some(size) = entry.thread_data_size {
                    println!("        thread_data_size: {}", size);
                }
            }
        }

        if cli.all || cli.version {
            if let Some(ref version) = macho.version_info {
                println!("\n[Version Information]");
                println!("        platform:    {}", version.platform);
                println!("        min_version: {}", version.min_version);
                println!("        sdk_version: {}", version.sdk_version);
            } else if cli.all {
                println!("\n[Version Information]\n        No version information found");
            }
        }

        if cli.all || cli.signature {
            if let Some(ref sig) = macho.code_signature {
                print_code_signature(sig);
            } else if cli.all {
                println!("\n[Code Signature]\n        Not signed");
            }
        }

        if cli.all || cli.imports {
            print_imports(macho);
        }

        if cli.all || cli.exports {
            print_exports(macho);
        }

        if cli.all || cli.similarity {
            if let Some(ref hashes) = macho.similarity_hashes {
                print_similarity_hashes(hashes);
            }
        }
    }
}

fn print_general_info(universal: &UniversalMachO) {
    println!("\n[General File Info]");
    if let Some(ref filename) = universal.general_info.filename {
        println!("        Filename:         {}", filename);
    }
    println!(
        "        Filesize:         {}",
        universal.general_info.filesize
    );
    println!("        MD5:              {}", universal.general_info.md5);
    println!("        SHA1:             {}", universal.general_info.sha1);
    println!(
        "        SHA256:           {}",
        universal.general_info.sha256
    );
}

fn print_header(macho: &MachO) {
    println!("\n[Mach-O Header]");

    let magic_str = match macho.header.magic() {
        MH_MAGIC => "MH_MAGIC (32-bit)",
        MH_CIGAM => "MH_CIGAM (32-bit reversed)",
        MH_MAGIC_64 => "MH_MAGIC_64 (64-bit)",
        MH_CIGAM_64 => "MH_CIGAM_64 (64-bit reversed)",
        _ => "Unknown",
    };

    println!(
        "        magic:            {}, {:#x}",
        magic_str,
        macho.header.magic()
    );
    println!(
        "        cputype:          {}",
        get_cpu_type_name(macho.header.cputype() as u32)
    );
    println!(
        "        cpusubtype:       {}",
        get_cpu_subtype_name(
            macho.header.cputype() as u32,
            macho.header.cpusubtype() as u32
        )
    );
    println!(
        "        filetype:         {}",
        get_file_type_name(macho.header.filetype())
    );
    println!("        ncmds:            {}", macho.header.ncmds());
    println!("        sizeofcmds:       {}", macho.header.sizeofcmds());

    let flags = get_header_flags(macho.header.flags());
    if !flags.is_empty() {
        println!("        flags:            {}", flags.join(", "));
    } else {
        println!("        flags:            None");
    }
}

fn print_load_commands(macho: &MachO) {
    println!("\n[Load Cmd table]");
    for cmd in &macho.load_commands {
        let (cmd_type, cmd_size) = match cmd {
            LoadCommandData::Segment32(s) => (get_load_command_name(s.cmd), s.cmdsize),
            LoadCommandData::Segment64(s) => (get_load_command_name(s.cmd), s.cmdsize),
            LoadCommandData::Dylib(d, _) => (get_load_command_name(d.cmd), d.cmdsize),
            LoadCommandData::Symtab(s) => (get_load_command_name(s.cmd), s.cmdsize),
            LoadCommandData::Dysymtab(d) => (get_load_command_name(d.cmd), d.cmdsize),
            LoadCommandData::Uuid(u) => (get_load_command_name(u.cmd), u.cmdsize),
            LoadCommandData::Main(m) => (get_load_command_name(m.cmd), m.cmdsize),
            LoadCommandData::Other(o) => (get_load_command_name(o.cmd), o.cmdsize),
            _ => ("Unknown", 0),
        };
        println!("        {{'cmd': '{}', 'cmdsize': {}}}", cmd_type, cmd_size);
    }

    // Print unique command types
    let mut unique_cmds = std::collections::HashSet::new();
    for cmd in &macho.load_commands {
        let cmd_type = match cmd {
            LoadCommandData::Segment32(s) => get_load_command_name(s.cmd),
            LoadCommandData::Segment64(s) => get_load_command_name(s.cmd),
            LoadCommandData::Dylib(d, _) => get_load_command_name(d.cmd),
            LoadCommandData::Symtab(s) => get_load_command_name(s.cmd),
            LoadCommandData::Dysymtab(d) => get_load_command_name(d.cmd),
            LoadCommandData::Uuid(u) => get_load_command_name(u.cmd),
            LoadCommandData::Main(m) => get_load_command_name(m.cmd),
            LoadCommandData::Other(o) => get_load_command_name(o.cmd),
            _ => "Unknown",
        };
        unique_cmds.insert(cmd_type);
    }

    println!("\n[Load Commands]");
    for cmd in unique_cmds {
        println!("        {}", cmd);
    }
}

fn print_segments(macho: &MachO) {
    println!("\n[File Segments]");
    println!("        SEGNAME    VADDR VSIZE OFFSET SIZE  MAX_VM_PROTECTION INITIAL_VM_PROTECTION NSECTS FLAGS ENTROPY");
    println!("        ------------------------------------------------------------------------------------------------------------");

    for segment in &macho.segments {
        println!(
            "        {:<10} {:<5} {:<5} {:<6} {:<5} {:<17} {:<21} {:<6} {:<5} {:.15}",
            segment.name,
            segment.vmaddr,
            segment.vmsize,
            segment.fileoff,
            segment.filesize,
            segment.maxprot,
            segment.initprot,
            segment.nsects,
            segment.flags,
            segment.entropy
        );
    }
}

fn print_dylibs(macho: &MachO) {
    if macho.dylibs.is_empty() {
        return;
    }

    println!("\n[Dylib Commands]");
    println!("        DYLIB_NAME_OFFSET DYLIB_TIMESTAMP DYLIB_CURRENT_VERSION DYLIB_COMPAT_VERSION DYLIB_NAME");
    println!("        ----------------------------------------------------------------------------------------------------------");

    for dylib in &macho.dylibs {
        println!(
            "        {:<17} {:<16} {:<22} {:<20} {}",
            24, // Typical offset
            dylib.timestamp,
            dylib.current_version,
            dylib.compatibility_version,
            dylib.name
        );
    }

    println!("\n[Dylib Names]");
    for dylib in &macho.dylibs {
        println!("        {}", dylib.name);
    }
}

fn print_imports(macho: &MachO) {
    if macho.imported_symbols.is_empty() {
        return;
    }

    println!("\n[Imported Functions]");
    for import in &macho.imported_symbols {
        println!("        {}:", import.dylib);
        for symbol in &import.symbols {
            println!("                {}", symbol);
        }
    }
}

fn print_exports(macho: &MachO) {
    if macho.exported_symbols.is_empty() {
        return;
    }

    println!("\n[Exported Symbols]");
    println!("        <unknown>:");
    for symbol in &macho.exported_symbols {
        println!("                {}", symbol);
    }
}

fn print_code_signature(sig: &CodeSignature) {
    println!("\n[Code Signature]");
    println!("        signed:           {}", sig.signed);
    println!("        signing_status:   {}", sig.signing_status);

    if !sig.certificates.is_empty() {
        println!("        certificates_info:");
        println!("            count:            {}", sig.certificates.len());
        println!("            certificates:");

        for cert in &sig.certificates {
            println!("              index:            {}", cert.index);
            println!("              size:             {}", cert.size);
            println!("              subject:          {}", cert.subject);
            println!("              issuer:           {}", cert.issuer);
            println!("              is_apple_cert:    {}", cert.is_apple_cert);
            println!("              type:             {}", cert.cert_type);
            println!();
        }
    }

    if !sig.entitlements.is_empty() {
        println!("        entitlements_info:");
        println!("            count:            {}", sig.entitlements.len());
        println!("            entitlements:");
        for ent in &sig.entitlements {
            println!("                {}", ent);
        }
    }

    if let Some(ref cd) = sig.code_directory {
        println!("        code_directory:");
        println!("            version:          {}", cd.version);
        println!("            flags:            {}", cd.flags);
        println!("            hash_offset:      {}", cd.hash_offset);
        println!("            identifier_offset:{}", cd.identifier_offset);
        println!("            special_slots:    {}", cd.special_slots);
        println!("            code_slots:       {}", cd.code_slots);
        println!("            hash_size:        {}", cd.hash_size);
        println!("            hash_type:        {}", cd.hash_type);
        println!("            hash_algorithm:   {}", cd.hash_algorithm);
        println!("            identifier:       {}", cd.identifier);
    }
}

fn print_similarity_hashes(hashes: &SimilarityHashes) {
    println!("\n[Similarity Hashes]");
    println!("        dylib_hash:       {}", hashes.dylib_hash);
    println!("        export_hash:      {}", hashes.export_hash);
    println!("        import_hash:      {}", hashes.import_hash);
    println!("        symhash:          {}", hashes.symhash);
    if let Some(ref ent_hash) = hashes.entitlement_hash {
        println!("        entitlement_hash: {}", ent_hash);
    }
}

fn get_raw_header_info(header: &MachHeader) -> serde_json::Value {
    match header {
        MachHeader::MachO32(h) => serde_json::json!({
            "magic": h.magic,
            "cputype": h.cputype,
            "cpusubtype": h.cpusubtype,
            "filetype": h.filetype,
            "ncmds": h.ncmds,
            "sizeofcmds": h.sizeofcmds,
            "flags": h.flags,
        }),
        MachHeader::MachO64(h) => serde_json::json!({
            "magic": h.magic,
            "cputype": h.cputype,
            "cpusubtype": h.cpusubtype,
            "filetype": h.filetype,
            "ncmds": h.ncmds,
            "sizeofcmds": h.sizeofcmds,
            "flags": h.flags,
            "reserved": h.reserved,
        }),
    }
}

fn get_formatted_header_info(header: &MachHeader) -> serde_json::Value {
    let magic_str = match header.magic() {
        MH_MAGIC => "MH_MAGIC (32-bit)",
        MH_CIGAM => "MH_CIGAM (32-bit reversed)",
        MH_MAGIC_64 => "MH_MAGIC_64 (64-bit)",
        MH_CIGAM_64 => "MH_CIGAM_64 (64-bit reversed)",
        _ => "Unknown",
    };

    let flags = get_header_flags(header.flags());
    let flags_str = if flags.is_empty() {
        "None".to_string()
    } else {
        flags.join(", ")
    };

    serde_json::json!({
        "magic": format!("{}, {:#x}", magic_str, header.magic()),
        "cputype": get_cpu_type_name(header.cputype() as u32),
        "cpusubtype": get_cpu_subtype_name(header.cputype() as u32, header.cpusubtype() as u32),
        "filetype": get_file_type_name(header.filetype()),
        "ncmds": header.ncmds(),
        "sizeofcmds": header.sizeofcmds(),
        "flags": flags_str,
    })
}
