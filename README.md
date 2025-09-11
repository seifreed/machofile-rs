# machofile-rs
**machofile-rs** is a high-performance Rust implementation for parsing Mach-O binary files, with a focus on malware analysis and reverse engineering.

This project is a complete port of the original Python [machofile](https://github.com/pstirparo/machofile) project by [Pasquale Stirparo](https://github.com/pstirparo) to Rust, providing 100% feature parity with significantly improved performance and memory safety.

## Why Rust Port?
- **Performance**: 10x+ faster parsing compared to Python implementation
- **Memory Safety**: Zero-copy parsing with Rust's memory safety guarantees  
- **Cross-platform**: Single binary deployment without runtime dependencies
- **Malware Analysis**: Improved security for analyzing potentially malicious binaries

**Special thanks to [Pasquale Stirparo](https://github.com/pstirparo) for creating the original Python implementation that served as the foundation for this Rust port.**

## Features

**machofile-rs** is self-contained with no runtime dependencies. It is endianness independent and works on macOS, Windows, and Linux.

**Current Features:**
- Parse Mach-O Header (32-bit and 64-bit)
- Parse all Load Commands (54+ supported)
- Parse File Segments with entropy calculation
- Parse Dylib Commands and dependencies
- Extract imported and exported symbols
- Code signature analysis (certificates, entitlements, CodeDirectory)
- Similarity hashes: dylib hash, import hash, export hash, entitlement hash, symhash
- Entry point extraction (LC_MAIN, LC_UNIXTHREAD)
- UUID extraction
- Version information parsing
- Support for Universal (FAT) binaries
- JSON output support (both human-readable and raw formats)

_Tested against x86, x86_64, arm64, and arm64e Mach-O samples._

## Installation

### Download Pre-built Binaries

Download the latest release for your platform from the [Releases page](https://github.com/seifreed/machofile-rs/releases):

**macOS:**
- Intel Macs: `machofile-x86_64-apple-darwin.tar.gz`
- Apple Silicon: `machofile-aarch64-apple-darwin.tar.gz`

**Linux:**
- x64: `machofile-x86_64-unknown-linux-gnu.tar.gz`
- ARM64: `machofile-aarch64-unknown-linux-gnu.tar.gz`

**Windows:**
- x64: `machofile-x86_64-pc-windows-msvc.zip`

### Build from Source

```bash
# Clone the repository
git clone https://github.com/seifreed/machofile-rs.git
cd machofile-rs

# Build the project
cargo build --release

# The binary will be available at ./target/release/machofile
```

## Usage

### Command Line Interface

```bash
machofile -f /path/to/binary [OPTIONS]
```

**Options:**
```
  -f, --file <FILE>   Path to the file to be parsed [REQUIRED]
  -j, --json          Output data in JSON format
      --raw           Output raw values in JSON format (use with -j)
  -a, --all           Print all info about the file
  -d, --dylib         Print Dylib Command Table and Dylib list
  -e, --exports       Print exported symbols
      --ep            Print entry point information
  -g, --general_info  Print general info about the file
      --header        Print Mach-O header info
  -i, --imports       Print imported symbols
  -l, --load_cmd_t    Print Load Command Table and Command list
      --segments      Print File Segments info
      --signature     Print code signature and entitlements information
      --similarity    Print similarity hashes
  -u, --uuid          Print UUID
  -v, --version       Print version information
      --arch <ARCH>   Show info for specific architecture only (for Universal binaries)
  -h, --help          Print help
```

### Examples

**Basic analysis:**
```bash
machofile -f /bin/ls -a
```

**JSON output:**
```bash
machofile -f /bin/ls -a --json
```

**Analyze specific architecture in Universal binary:**
```bash
machofile -f /usr/bin/file --arch arm64 -a
```

**Extract only imports and exports:**
```bash
machofile -f /bin/ls -i -e
```

**Get similarity hashes for malware analysis:**
```bash
machofile -f suspicious_binary --similarity
```

### Rust Library Usage

Add to your `Cargo.toml`:
```toml
[dependencies]
machofile = "1.0"
```

Example usage:
```rust
use machofile::{parse_file, UniversalMachO};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse a Mach-O file
    let universal = parse_file("/bin/ls")?;
    
    // Access general information
    println!("File size: {}", universal.general_info.filesize);
    println!("SHA256: {}", universal.general_info.sha256);
    
    // Iterate through architectures
    for (arch, macho) in &universal.machos {
        println!("Architecture: {}", arch);
        
        // Access header information
        println!("CPU Type: {:?}", macho.header.cputype());
        println!("File Type: {:?}", macho.header.filetype());
        
        // Access segments
        for segment in &macho.segments {
            println!("Segment: {} (entropy: {:.2})", segment.name, segment.entropy);
        }
        
        // Access imported symbols
        for import in &macho.imported_symbols {
            println!("Library: {}", import.dylib);
            for symbol in &import.symbols {
                println!("  - {}", symbol);
            }
        }
    }
    
    Ok(())
}
```

### JSON Output

**Human-Readable JSON (Default):**
```bash
machofile -f /bin/ls --header --json
```

**Raw JSON Output:**
```bash
machofile -f /bin/ls --header --json --raw
```

## Example Output

```
% machofile -f /bin/ls -a

[General File Info]
        Filename:         ls
        Filesize:         145456
        MD5:              a1b2c3d4e5f6789...
        SHA1:             9f8e7d6c5b4a321...
        SHA256:           1234567890abcdef...

[Mach-O Header]
        magic:            MH_MAGIC_64 (64-bit), 0xFEEDFACF
        cputype:          x86_64
        cpusubtype:       x86_ALL
        filetype:         EXECUTE
        ncmds:            29
        sizeofcmds:       4320
        flags:            NOUNDEFS, DYLDLINK, TWOLEVEL, PIE

[File Segments]
        SEGNAME    VADDR VSIZE OFFSET SIZE  MAX_VM_PROTECTION INITIAL_VM_PROTECTION NSECTS FLAGS ENTROPY
        --------------------------------------------------------------------------------------------------------
        __PAGEZERO 0     4096  0      0     0                 0                     0      0     0.0
        __TEXT     4096  32768 0      32768 7                 5                     4      0     5.234567
        __DATA     36864 4096  32768  4096  7                 3                     3      0     2.345678

[Similarity Hashes]
        dylib_hash:       a1b2c3d4e5f6789012345678901234567
        export_hash:      b2c3d4e5f67890123456789012345678
        import_hash:      c3d4e5f6789012345678901234567890
        symhash:          d4e5f67890123456789012345678901a
```

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Credits

- [Pasquale Stirparo](https://github.com/pstirparo) - Original Python implementation
- Ero Carrera ([@erocarrera](https://twitter.com/erocarrera)) - [pefile](https://github.com/erocarrera/pefile) inspiration
- Patrick Wardle ([@patrickwardle](https://twitter.com/patrickwardle)) - macOS security research
- Greg Lesnewich & Jacob Latonis - Mach-O similarity research

## Reference Documentation
- [Apple's Mach-O loader.h](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h)
- [LLDB Mach-O Support](https://github.com/apple-oss-distributions/lldb/blob/main/llvm/include/llvm/Support/MachO.h)
- [Mach-O File Format](https://iphonedev.wiki/Mach-O_File_Format)
- [Parsing Mach-O Files](https://lowlevelbits.org/parsing-mach-o-files/)
- [OSX ABI Mach-O Reference](https://github.com/aidansteele/osx-abi-macho-file-format-reference)