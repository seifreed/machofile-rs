//! Mach-O file parser implementation

use crate::constants::*;
use crate::errors::{Error, Result};
use crate::structs::*;
use crate::utils::*;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use std::collections::HashMap;
use std::io::{Cursor, Read, Seek, SeekFrom};

pub struct UniversalMachO {
    pub data: Vec<u8>,
    pub is_universal: bool,
    pub fat_header: Option<FatHeader>,
    pub fat_archs: Vec<FatArch>,
    pub fat_archs_64: Vec<FatArch64>,
    pub machos: HashMap<String, MachO>,
    pub general_info: GeneralInfo,
}

impl UniversalMachO {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::InvalidFormat);
        }

        let mut cursor = Cursor::new(data);
        let magic = cursor.read_u32::<BigEndian>()?;
        cursor.seek(SeekFrom::Start(0))?;

        let general_info = GeneralInfo {
            filename: None,
            filesize: data.len(),
            md5: calculate_md5(data),
            sha1: calculate_sha1(data),
            sha256: calculate_sha256(data),
        };

        if is_fat_magic(magic) {
            Self::parse_universal(data, general_info)
        } else {
            // Single architecture binary
            let macho = MachO::parse(data, 0)?;
            let arch_name = get_arch_name(macho.header.cputype());

            let mut machos = HashMap::new();
            machos.insert(arch_name, macho);

            Ok(UniversalMachO {
                data: data.to_vec(),
                is_universal: false,
                fat_header: None,
                fat_archs: Vec::new(),
                fat_archs_64: Vec::new(),
                machos,
                general_info,
            })
        }
    }

    fn parse_universal(data: &[u8], general_info: GeneralInfo) -> Result<Self> {
        let mut cursor = Cursor::new(data);
        let magic = cursor.read_u32::<BigEndian>()?;

        let (is_little_endian, _) = detect_endianness(magic);
        let is_64 = is_64_bit_magic(magic);

        cursor.seek(SeekFrom::Start(0))?;

        let (fat_header, fat_archs, fat_archs_64) = if is_64 {
            let header = Self::read_fat_header_64(&mut cursor, is_little_endian)?;
            let archs = Self::read_fat_archs_64(&mut cursor, header.nfat_arch, is_little_endian)?;
            (header, Vec::new(), archs)
        } else {
            let header = Self::read_fat_header(&mut cursor, is_little_endian)?;
            let archs = Self::read_fat_archs(&mut cursor, header.nfat_arch, is_little_endian)?;
            (header, archs, Vec::new())
        };

        let mut machos = HashMap::new();

        if is_64 {
            for arch in &fat_archs_64 {
                let arch_data = &data[arch.offset as usize..(arch.offset + arch.size) as usize];
                let macho = MachO::parse(arch_data, arch.offset)?;
                let arch_name = get_arch_name(arch.cputype);
                machos.insert(arch_name, macho);
            }
        } else {
            for arch in &fat_archs {
                let arch_data = &data[arch.offset as usize..(arch.offset + arch.size) as usize];
                let macho = MachO::parse(arch_data, arch.offset as u64)?;
                let arch_name = get_arch_name(arch.cputype);
                machos.insert(arch_name, macho);
            }
        }

        Ok(UniversalMachO {
            data: data.to_vec(),
            is_universal: true,
            fat_header: Some(fat_header),
            fat_archs,
            fat_archs_64,
            machos,
            general_info,
        })
    }

    fn read_fat_header<R: Read>(cursor: &mut R, is_little_endian: bool) -> Result<FatHeader> {
        let magic = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let nfat_arch = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        Ok(FatHeader { magic, nfat_arch })
    }

    fn read_fat_header_64<R: Read>(cursor: &mut R, is_little_endian: bool) -> Result<FatHeader> {
        Self::read_fat_header(cursor, is_little_endian)
    }

    fn read_fat_archs<R: Read>(
        cursor: &mut R,
        count: u32,
        is_little_endian: bool,
    ) -> Result<Vec<FatArch>> {
        let mut archs = Vec::new();

        for _ in 0..count {
            let cputype = if is_little_endian {
                cursor.read_i32::<LittleEndian>()?
            } else {
                cursor.read_i32::<BigEndian>()?
            };

            let cpusubtype = if is_little_endian {
                cursor.read_i32::<LittleEndian>()?
            } else {
                cursor.read_i32::<BigEndian>()?
            };

            let offset = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            let size = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            let align = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            archs.push(FatArch {
                cputype,
                cpusubtype,
                offset,
                size,
                align,
            });
        }

        Ok(archs)
    }

    fn read_fat_archs_64<R: Read>(
        cursor: &mut R,
        count: u32,
        is_little_endian: bool,
    ) -> Result<Vec<FatArch64>> {
        let mut archs = Vec::new();

        for _ in 0..count {
            let cputype = if is_little_endian {
                cursor.read_i32::<LittleEndian>()?
            } else {
                cursor.read_i32::<BigEndian>()?
            };

            let cpusubtype = if is_little_endian {
                cursor.read_i32::<LittleEndian>()?
            } else {
                cursor.read_i32::<BigEndian>()?
            };

            let offset = if is_little_endian {
                cursor.read_u64::<LittleEndian>()?
            } else {
                cursor.read_u64::<BigEndian>()?
            };

            let size = if is_little_endian {
                cursor.read_u64::<LittleEndian>()?
            } else {
                cursor.read_u64::<BigEndian>()?
            };

            let align = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            let reserved = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            archs.push(FatArch64 {
                cputype,
                cpusubtype,
                offset,
                size,
                align,
                reserved,
            });
        }

        Ok(archs)
    }
}

pub struct MachO {
    pub data: Vec<u8>,
    pub offset: u64,
    pub header: MachHeader,
    pub load_commands: Vec<LoadCommandData>,
    pub segments: Vec<Segment>,
    pub dylibs: Vec<DylibInfo>,
    pub imported_symbols: Vec<ImportedSymbol>,
    pub exported_symbols: Vec<String>,
    pub uuid: Option<String>,
    pub entry_point: Option<EntryPoint>,
    pub version_info: Option<VersionInfo>,
    pub code_signature: Option<CodeSignature>,
    pub similarity_hashes: Option<SimilarityHashes>,
    is_little_endian: bool,
}

#[derive(Debug, Clone)]
pub enum LoadCommandData {
    Segment32(SegmentCommand32),
    Segment64(SegmentCommand64),
    Dylib(DylibCommand, Vec<u8>), // Include raw command data for name extraction
    Symtab(SymtabCommand),
    Dysymtab(DysymtabCommand),
    Uuid(UuidCommand),
    DyldInfo(DyldInfoCommand),
    LinkeditData(LinkeditDataCommand),
    Main(MainCommand),
    VersionMin(VersionMinCommand),
    BuildVersion(BuildVersionCommand),
    SourceVersion(SourceVersionCommand),
    EncryptionInfo(EncryptionInfoCommand),
    EncryptionInfo64(EncryptionInfoCommand64),
    Rpath(RpathCommand),
    LinkerOption(LinkerOptionCommand),
    Thread(ThreadCommand),
    UnixThread(ThreadCommand),
    Routines(RoutinesCommand),
    Routines64(RoutinesCommand64),
    SubFramework(SubFrameworkCommand),
    SubClient(SubClientCommand),
    SubLibrary(SubLibraryCommand),
    SubUmbrella(SubUmbrellaCommand),
    PreboundDylib(PreboundDylibCommand),
    Dylinker(DylinkerCommand),
    TwoLevelHints(TwoLevelHintsCommand),
    PrebindCksum(PrebindCksumCommand),
    FilesetEntry(FilesetEntryCommand),
    Note(NoteCommand),
    Other(LoadCommand),
}

impl MachO {
    pub fn parse(data: &[u8], offset: u64) -> Result<Self> {
        if data.len() < 28 {
            return Err(Error::InvalidFormat);
        }

        let mut cursor = Cursor::new(data);
        let magic = cursor.read_u32::<BigEndian>()?;
        cursor.seek(SeekFrom::Start(0))?;

        let (is_little_endian, _) = detect_endianness(magic);

        if !is_valid_magic(magic) {
            return Err(Error::InvalidMagic(magic));
        }

        let header = Self::read_header(&mut cursor, magic, is_little_endian)?;
        let load_commands = Self::read_load_commands(&mut cursor, &header, is_little_endian)?;

        let mut macho = MachO {
            data: data.to_vec(),
            offset,
            header: header.clone(),
            load_commands: load_commands.clone(),
            segments: Vec::new(),
            dylibs: Vec::new(),
            imported_symbols: Vec::new(),
            exported_symbols: Vec::new(),
            uuid: None,
            entry_point: None,
            version_info: None,
            code_signature: None,
            similarity_hashes: None,
            is_little_endian,
        };

        macho.parse_segments()?;
        macho.parse_dylibs()?;
        macho.parse_symbols()?;
        macho.parse_uuid()?;
        macho.parse_entry_point()?;
        macho.parse_version_info()?;
        macho.parse_code_signature()?;
        macho.calculate_similarity_hashes()?;

        Ok(macho)
    }

    fn read_header<R: Read + Seek>(
        cursor: &mut R,
        magic: u32,
        is_little_endian: bool,
    ) -> Result<MachHeader> {
        cursor.seek(SeekFrom::Start(0))?;

        if magic == MH_MAGIC || magic == MH_CIGAM {
            // 32-bit header
            let magic = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            let cputype = if is_little_endian {
                cursor.read_i32::<LittleEndian>()?
            } else {
                cursor.read_i32::<BigEndian>()?
            };

            let cpusubtype = if is_little_endian {
                cursor.read_i32::<LittleEndian>()?
            } else {
                cursor.read_i32::<BigEndian>()?
            };

            let filetype = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            let ncmds = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            let sizeofcmds = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            let flags = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            Ok(MachHeader::MachO32(MachHeader32 {
                magic,
                cputype,
                cpusubtype,
                filetype,
                ncmds,
                sizeofcmds,
                flags,
            }))
        } else {
            // 64-bit header
            let magic = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            let cputype = if is_little_endian {
                cursor.read_i32::<LittleEndian>()?
            } else {
                cursor.read_i32::<BigEndian>()?
            };

            let cpusubtype = if is_little_endian {
                cursor.read_i32::<LittleEndian>()?
            } else {
                cursor.read_i32::<BigEndian>()?
            };

            let filetype = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            let ncmds = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            let sizeofcmds = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            let flags = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            let reserved = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            Ok(MachHeader::MachO64(MachHeader64 {
                magic,
                cputype,
                cpusubtype,
                filetype,
                ncmds,
                sizeofcmds,
                flags,
                reserved,
            }))
        }
    }

    fn read_load_commands<R: Read + Seek>(
        cursor: &mut R,
        header: &MachHeader,
        is_little_endian: bool,
    ) -> Result<Vec<LoadCommandData>> {
        use crate::load_commands::*;

        let mut commands = Vec::new();

        for _ in 0..header.ncmds() {
            let cmd_start = cursor.stream_position()?;

            let cmd = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            let cmdsize = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            cursor.seek(SeekFrom::Start(cmd_start))?;

            let command_data = match cmd & !LC_REQ_DYLD {
                LC_SEGMENT | LC_SEGMENT_64 => {
                    Self::read_segment_command(cursor, cmd, is_little_endian)?
                }
                LC_LOAD_DYLIB | LC_ID_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB
                | LC_LAZY_LOAD_DYLIB | LC_LOAD_UPWARD_DYLIB => {
                    let dylib_cmd = Self::read_dylib_command(cursor, is_little_endian)?;
                    // Read the raw command data for name extraction
                    cursor.seek(SeekFrom::Start(cmd_start))?;
                    let mut cmd_data = vec![0u8; cmdsize as usize];
                    cursor.read_exact(&mut cmd_data)?;
                    LoadCommandData::Dylib(dylib_cmd, cmd_data)
                }
                LC_SYMTAB => {
                    LoadCommandData::Symtab(Self::read_symtab_command(cursor, is_little_endian)?)
                }
                LC_DYSYMTAB => LoadCommandData::Dysymtab(Self::read_dysymtab_command(
                    cursor,
                    is_little_endian,
                )?),
                LC_UUID => {
                    LoadCommandData::Uuid(Self::read_uuid_command(cursor, is_little_endian)?)
                }
                LC_MAIN => {
                    LoadCommandData::Main(Self::read_main_command(cursor, is_little_endian)?)
                }
                LC_DYLD_INFO | LC_DYLD_INFO_ONLY => LoadCommandData::DyldInfo(
                    Self::read_dyld_info_command(cursor, is_little_endian)?,
                ),
                LC_VERSION_MIN_MACOSX
                | LC_VERSION_MIN_IPHONEOS
                | LC_VERSION_MIN_TVOS
                | LC_VERSION_MIN_WATCHOS => LoadCommandData::VersionMin(
                    Self::read_version_min_command(cursor, is_little_endian)?,
                ),
                LC_BUILD_VERSION => LoadCommandData::BuildVersion(
                    Self::read_build_version_command(cursor, is_little_endian)?,
                ),
                LC_SOURCE_VERSION => LoadCommandData::SourceVersion(
                    Self::read_source_version_command(cursor, is_little_endian)?,
                ),
                LC_ENCRYPTION_INFO => LoadCommandData::EncryptionInfo(
                    read_encryption_info_command(cursor, is_little_endian)?,
                ),
                LC_ENCRYPTION_INFO_64 => LoadCommandData::EncryptionInfo64(
                    read_encryption_info_command_64(cursor, is_little_endian)?,
                ),
                LC_RPATH => LoadCommandData::Rpath(read_rpath_command(cursor, is_little_endian)?),
                LC_CODE_SIGNATURE
                | LC_FUNCTION_STARTS
                | LC_DATA_IN_CODE
                | LC_DYLIB_CODE_SIGN_DRS
                | LC_LINKER_OPTIMIZATION_HINT
                | LC_SEGMENT_SPLIT_INFO
                | LC_DYLD_EXPORTS_TRIE
                | LC_DYLD_CHAINED_FIXUPS => LoadCommandData::LinkeditData(
                    read_linkedit_data_command(cursor, is_little_endian)?,
                ),
                LC_THREAD => {
                    LoadCommandData::Thread(read_thread_command(cursor, is_little_endian)?)
                }
                LC_UNIXTHREAD => {
                    LoadCommandData::UnixThread(read_thread_command(cursor, is_little_endian)?)
                }
                LC_LOAD_DYLINKER | LC_ID_DYLINKER | LC_DYLD_ENVIRONMENT => {
                    LoadCommandData::Dylinker(read_dylinker_command(cursor, is_little_endian)?)
                }
                LC_ROUTINES => {
                    LoadCommandData::Routines(read_routines_command(cursor, is_little_endian)?)
                }
                LC_ROUTINES_64 => {
                    LoadCommandData::Routines64(read_routines_command_64(cursor, is_little_endian)?)
                }
                LC_SUB_FRAMEWORK => LoadCommandData::SubFramework(read_sub_framework_command(
                    cursor,
                    is_little_endian,
                )?),
                LC_SUB_CLIENT => {
                    LoadCommandData::SubClient(read_sub_client_command(cursor, is_little_endian)?)
                }
                LC_SUB_LIBRARY => {
                    LoadCommandData::SubLibrary(read_sub_library_command(cursor, is_little_endian)?)
                }
                LC_SUB_UMBRELLA => LoadCommandData::SubUmbrella(read_sub_umbrella_command(
                    cursor,
                    is_little_endian,
                )?),
                LC_PREBOUND_DYLIB => LoadCommandData::PreboundDylib(read_prebound_dylib_command(
                    cursor,
                    is_little_endian,
                )?),
                LC_TWOLEVEL_HINTS => LoadCommandData::TwoLevelHints(read_twolevel_hints_command(
                    cursor,
                    is_little_endian,
                )?),
                LC_PREBIND_CKSUM => LoadCommandData::PrebindCksum(read_prebind_cksum_command(
                    cursor,
                    is_little_endian,
                )?),
                LC_LINKER_OPTION => LoadCommandData::LinkerOption(read_linker_option_command(
                    cursor,
                    is_little_endian,
                )?),
                LC_NOTE => LoadCommandData::Note(read_note_command(cursor, is_little_endian)?),
                LC_FILESET_ENTRY => LoadCommandData::FilesetEntry(read_fileset_entry_command(
                    cursor,
                    is_little_endian,
                )?),
                _ => LoadCommandData::Other(LoadCommand { cmd, cmdsize }),
            };

            commands.push(command_data);
            cursor.seek(SeekFrom::Start(cmd_start + cmdsize as u64))?;
        }

        Ok(commands)
    }

    fn read_segment_command<R: Read>(
        cursor: &mut R,
        cmd: u32,
        is_little_endian: bool,
    ) -> Result<LoadCommandData> {
        if cmd == LC_SEGMENT {
            let cmd = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            let cmdsize = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            let mut segname = [0u8; 16];
            cursor.read_exact(&mut segname)?;

            let vmaddr = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            let vmsize = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            let fileoff = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            let filesize = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            let maxprot = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            let initprot = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            let nsects = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            let flags = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            Ok(LoadCommandData::Segment32(SegmentCommand32 {
                cmd,
                cmdsize,
                segname,
                vmaddr,
                vmsize,
                fileoff,
                filesize,
                maxprot,
                initprot,
                nsects,
                flags,
            }))
        } else {
            let cmd = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            let cmdsize = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            let mut segname = [0u8; 16];
            cursor.read_exact(&mut segname)?;

            let vmaddr = if is_little_endian {
                cursor.read_u64::<LittleEndian>()?
            } else {
                cursor.read_u64::<BigEndian>()?
            };

            let vmsize = if is_little_endian {
                cursor.read_u64::<LittleEndian>()?
            } else {
                cursor.read_u64::<BigEndian>()?
            };

            let fileoff = if is_little_endian {
                cursor.read_u64::<LittleEndian>()?
            } else {
                cursor.read_u64::<BigEndian>()?
            };

            let filesize = if is_little_endian {
                cursor.read_u64::<LittleEndian>()?
            } else {
                cursor.read_u64::<BigEndian>()?
            };

            let maxprot = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            let initprot = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            let nsects = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            let flags = if is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };

            Ok(LoadCommandData::Segment64(SegmentCommand64 {
                cmd,
                cmdsize,
                segname,
                vmaddr,
                vmsize,
                fileoff,
                filesize,
                maxprot,
                initprot,
                nsects,
                flags,
            }))
        }
    }

    fn read_dylib_command<R: Read>(cursor: &mut R, is_little_endian: bool) -> Result<DylibCommand> {
        let cmd = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let cmdsize = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let name_offset = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let timestamp = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let current_version = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let compatibility_version = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        Ok(DylibCommand {
            cmd,
            cmdsize,
            dylib: Dylib {
                name: name_offset,
                timestamp,
                current_version,
                compatibility_version,
            },
        })
    }

    fn read_symtab_command<R: Read>(
        cursor: &mut R,
        is_little_endian: bool,
    ) -> Result<SymtabCommand> {
        let cmd = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let cmdsize = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let symoff = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let nsyms = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let stroff = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let strsize = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        Ok(SymtabCommand {
            cmd,
            cmdsize,
            symoff,
            nsyms,
            stroff,
            strsize,
        })
    }

    fn read_dysymtab_command<R: Read>(
        cursor: &mut R,
        is_little_endian: bool,
    ) -> Result<DysymtabCommand> {
        let cmd = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let cmdsize = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let ilocalsym = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let nlocalsym = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let iextdefsym = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let nextdefsym = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let iundefsym = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let nundefsym = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let tocoff = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let ntoc = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let modtaboff = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let nmodtab = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let extrefsymoff = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let nextrefsyms = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let indirectsymoff = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let nindirectsyms = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let extreloff = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let nextrel = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let locreloff = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let nlocrel = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        Ok(DysymtabCommand {
            cmd,
            cmdsize,
            ilocalsym,
            nlocalsym,
            iextdefsym,
            nextdefsym,
            iundefsym,
            nundefsym,
            tocoff,
            ntoc,
            modtaboff,
            nmodtab,
            extrefsymoff,
            nextrefsyms,
            indirectsymoff,
            nindirectsyms,
            extreloff,
            nextrel,
            locreloff,
            nlocrel,
        })
    }

    fn read_uuid_command<R: Read>(cursor: &mut R, is_little_endian: bool) -> Result<UuidCommand> {
        let cmd = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let cmdsize = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let mut uuid = [0u8; 16];
        cursor.read_exact(&mut uuid)?;

        Ok(UuidCommand { cmd, cmdsize, uuid })
    }

    fn read_dyld_info_command<R: Read>(
        cursor: &mut R,
        is_little_endian: bool,
    ) -> Result<DyldInfoCommand> {
        let cmd = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let cmdsize = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let rebase_off = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let rebase_size = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let bind_off = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let bind_size = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let weak_bind_off = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let weak_bind_size = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let lazy_bind_off = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let lazy_bind_size = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let export_off = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let export_size = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        Ok(DyldInfoCommand {
            cmd,
            cmdsize,
            rebase_off,
            rebase_size,
            bind_off,
            bind_size,
            weak_bind_off,
            weak_bind_size,
            lazy_bind_off,
            lazy_bind_size,
            export_off,
            export_size,
        })
    }

    fn read_version_min_command<R: Read>(
        cursor: &mut R,
        is_little_endian: bool,
    ) -> Result<VersionMinCommand> {
        let cmd = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let cmdsize = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let version = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let sdk = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        Ok(VersionMinCommand {
            cmd,
            cmdsize,
            version,
            sdk,
        })
    }

    fn read_build_version_command<R: Read>(
        cursor: &mut R,
        is_little_endian: bool,
    ) -> Result<BuildVersionCommand> {
        let cmd = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let cmdsize = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let platform = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let minos = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let sdk = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let ntools = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        Ok(BuildVersionCommand {
            cmd,
            cmdsize,
            platform,
            minos,
            sdk,
            ntools,
        })
    }

    fn read_source_version_command<R: Read>(
        cursor: &mut R,
        is_little_endian: bool,
    ) -> Result<SourceVersionCommand> {
        let cmd = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let cmdsize = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let version = if is_little_endian {
            cursor.read_u64::<LittleEndian>()?
        } else {
            cursor.read_u64::<BigEndian>()?
        };

        Ok(SourceVersionCommand {
            cmd,
            cmdsize,
            version,
        })
    }

    fn read_main_command<R: Read>(cursor: &mut R, is_little_endian: bool) -> Result<MainCommand> {
        let cmd = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let cmdsize = if is_little_endian {
            cursor.read_u32::<LittleEndian>()?
        } else {
            cursor.read_u32::<BigEndian>()?
        };

        let entryoff = if is_little_endian {
            cursor.read_u64::<LittleEndian>()?
        } else {
            cursor.read_u64::<BigEndian>()?
        };

        let stacksize = if is_little_endian {
            cursor.read_u64::<LittleEndian>()?
        } else {
            cursor.read_u64::<BigEndian>()?
        };

        Ok(MainCommand {
            cmd,
            cmdsize,
            entryoff,
            stacksize,
        })
    }

    fn parse_segments(&mut self) -> Result<()> {
        for cmd in &self.load_commands {
            match cmd {
                LoadCommandData::Segment32(seg) => {
                    let name = read_fixed_string(&seg.segname);
                    let segment_data = if seg.filesize > 0 {
                        &self.data[seg.fileoff as usize..(seg.fileoff + seg.filesize) as usize]
                    } else {
                        &[]
                    };

                    self.segments.push(Segment {
                        name,
                        vmaddr: seg.vmaddr as u64,
                        vmsize: seg.vmsize as u64,
                        fileoff: seg.fileoff as u64,
                        filesize: seg.filesize as u64,
                        maxprot: seg.maxprot,
                        initprot: seg.initprot,
                        nsects: seg.nsects,
                        flags: seg.flags,
                        entropy: calculate_entropy(segment_data),
                        sections: Vec::new(),
                    });
                }
                LoadCommandData::Segment64(seg) => {
                    let name = read_fixed_string(&seg.segname);
                    let segment_data = if seg.filesize > 0 {
                        &self.data[seg.fileoff as usize..(seg.fileoff + seg.filesize) as usize]
                    } else {
                        &[]
                    };

                    self.segments.push(Segment {
                        name,
                        vmaddr: seg.vmaddr,
                        vmsize: seg.vmsize,
                        fileoff: seg.fileoff,
                        filesize: seg.filesize,
                        maxprot: seg.maxprot,
                        initprot: seg.initprot,
                        nsects: seg.nsects,
                        flags: seg.flags,
                        entropy: calculate_entropy(segment_data),
                        sections: Vec::new(),
                    });
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn parse_dylibs(&mut self) -> Result<()> {
        for cmd in &self.load_commands {
            if let LoadCommandData::Dylib(dylib_cmd, cmd_data) = cmd {
                let name = if dylib_cmd.dylib.name as usize >= dylib_cmd.cmdsize as usize {
                    String::from("<invalid>")
                } else {
                    // Name is stored right after the dylib structure
                    let name_offset = dylib_cmd.dylib.name as usize;
                    read_cstring(cmd_data, name_offset)
                        .unwrap_or_else(|_| String::from("<invalid>"))
                };

                self.dylibs.push(DylibInfo {
                    name,
                    timestamp: dylib_cmd.dylib.timestamp,
                    current_version: dylib_cmd.dylib.current_version,
                    compatibility_version: dylib_cmd.dylib.compatibility_version,
                });
            }
        }
        Ok(())
    }

    fn parse_symbols(&mut self) -> Result<()> {
        use crate::symbol_parser::{
            parse_export_trie, parse_exported_symbols, parse_imported_symbols,
        };

        let mut symtab_cmd = None;
        let mut dysymtab_cmd = None;
        let mut dyld_info_cmd = None;

        // Find symbol-related commands
        for cmd in &self.load_commands {
            match cmd {
                LoadCommandData::Symtab(s) => symtab_cmd = Some(s.clone()),
                LoadCommandData::Dysymtab(d) => dysymtab_cmd = Some(d.clone()),
                LoadCommandData::DyldInfo(d) => dyld_info_cmd = Some(d.clone()),
                _ => {}
            }
        }

        // Parse imported symbols
        if let (Some(symtab), Some(dysymtab)) = (&symtab_cmd, &dysymtab_cmd) {
            self.imported_symbols = parse_imported_symbols(
                &self.data,
                symtab,
                dysymtab,
                &self.dylibs,
                self.is_little_endian,
                self.header.is_64_bit(),
            )?;

            // Parse exported symbols from symbol table
            let mut exports = parse_exported_symbols(
                &self.data,
                symtab,
                dysymtab,
                self.is_little_endian,
                self.header.is_64_bit(),
            )?;

            // Also try to parse from export trie if available
            if let Some(dyld_info) = &dyld_info_cmd {
                if dyld_info.export_size > 0 {
                    let trie_exports =
                        parse_export_trie(&self.data, dyld_info.export_off, dyld_info.export_size)?;
                    exports.extend(trie_exports);
                }
            }

            // Deduplicate exports
            exports.sort();
            exports.dedup();
            self.exported_symbols = exports;
        }

        Ok(())
    }

    fn parse_uuid(&mut self) -> Result<()> {
        for cmd in &self.load_commands {
            if let LoadCommandData::Uuid(uuid_cmd) = cmd {
                let uuid = uuid::Uuid::from_bytes(uuid_cmd.uuid);
                self.uuid = Some(uuid.to_string());
                break;
            }
        }
        Ok(())
    }

    fn parse_entry_point(&mut self) -> Result<()> {
        for cmd in &self.load_commands {
            match cmd {
                LoadCommandData::Main(main_cmd) => {
                    self.entry_point = Some(EntryPoint {
                        entry_type: "LC_MAIN".to_string(),
                        entry_address: main_cmd.entryoff,
                        thread_data_size: None,
                    });
                    break;
                }
                LoadCommandData::UnixThread(thread_cmd) => {
                    // Parse Unix thread entry point from thread state
                    // The entry point is typically in the first few bytes of thread data
                    let entry_address = if self.header.is_64_bit() {
                        // For 64-bit, entry point is typically at offset 16 (RIP register)
                        if thread_cmd.thread_state.len() >= 24 {
                            crate::utils::read_u64(
                                &thread_cmd.thread_state,
                                16,
                                self.is_little_endian,
                            )
                            .unwrap_or(0)
                        } else {
                            0
                        }
                    } else {
                        // For 32-bit, entry point is typically at offset 10 (EIP register)
                        if thread_cmd.thread_state.len() >= 14 {
                            crate::utils::read_u32(
                                &thread_cmd.thread_state,
                                10,
                                self.is_little_endian,
                            )
                            .unwrap_or(0) as u64
                        } else {
                            0
                        }
                    };

                    self.entry_point = Some(EntryPoint {
                        entry_type: "LC_UNIXTHREAD".to_string(),
                        entry_address,
                        thread_data_size: Some(thread_cmd.thread_state.len()),
                    });
                    break;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn parse_version_info(&mut self) -> Result<()> {
        for cmd in &self.load_commands {
            match cmd {
                LoadCommandData::VersionMin(v) => {
                    let platform = match v.cmd {
                        LC_VERSION_MIN_MACOSX => "macOS",
                        LC_VERSION_MIN_IPHONEOS => "iOS",
                        LC_VERSION_MIN_TVOS => "tvOS",
                        LC_VERSION_MIN_WATCHOS => "watchOS",
                        _ => "Unknown",
                    };

                    self.version_info = Some(VersionInfo {
                        platform: platform.to_string(),
                        min_version: crate::utils::format_version(v.version),
                        sdk_version: crate::utils::format_version(v.sdk),
                    });
                    break;
                }
                LoadCommandData::BuildVersion(b) => {
                    let platform = match b.platform {
                        1 => "macOS",
                        2 => "iOS",
                        3 => "tvOS",
                        4 => "watchOS",
                        5 => "bridgeOS",
                        6 => "Mac Catalyst",
                        7 => "iOS Simulator",
                        8 => "tvOS Simulator",
                        9 => "watchOS Simulator",
                        10 => "DriverKit",
                        _ => "Unknown",
                    };

                    self.version_info = Some(VersionInfo {
                        platform: platform.to_string(),
                        min_version: crate::utils::format_version(b.minos),
                        sdk_version: crate::utils::format_version(b.sdk),
                    });
                    break;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn parse_code_signature(&mut self) -> Result<()> {
        use crate::codesign::parse_code_signature;

        // Find LC_CODE_SIGNATURE command or LinkeditData command
        for cmd in &self.load_commands {
            match cmd {
                LoadCommandData::LinkeditData(lc) => {
                    // Check if this is LC_CODE_SIGNATURE
                    if lc.cmd == crate::constants::LC_CODE_SIGNATURE {
                        self.code_signature =
                            Some(parse_code_signature(&self.data, lc.dataoff, lc.datasize)?);
                        break;
                    }
                }
                LoadCommandData::Other(lc) => {
                    // Legacy fallback for LC_CODE_SIGNATURE in Other
                    if lc.cmd == crate::constants::LC_CODE_SIGNATURE {
                        // This shouldn't happen anymore since we handle it as LinkeditData
                        eprintln!("WARNING: LC_CODE_SIGNATURE found in Other command");
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn calculate_similarity_hashes(&mut self) -> Result<()> {
        use crate::symbol_parser::calculate_similarity_hashes;

        let entitlements = self
            .code_signature
            .as_ref()
            .map(|cs| cs.entitlements.clone())
            .unwrap_or_default();

        self.similarity_hashes = Some(calculate_similarity_hashes(
            &self.imported_symbols,
            &self.exported_symbols,
            &self.dylibs,
            &entitlements,
        ));

        Ok(())
    }
}
