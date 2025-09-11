//! Additional load command parsing functions

use crate::errors::Result;
use crate::structs::*;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use std::io::Read;

pub fn read_encryption_info_command<R: Read>(
    cursor: &mut R,
    is_little_endian: bool,
) -> Result<EncryptionInfoCommand> {
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

    let cryptoff = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    let cryptsize = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    let cryptid = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    Ok(EncryptionInfoCommand {
        cmd,
        cmdsize,
        cryptoff,
        cryptsize,
        cryptid,
    })
}

pub fn read_encryption_info_command_64<R: Read>(
    cursor: &mut R,
    is_little_endian: bool,
) -> Result<EncryptionInfoCommand64> {
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

    let cryptoff = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    let cryptsize = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    let cryptid = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    let pad = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    Ok(EncryptionInfoCommand64 {
        cmd,
        cmdsize,
        cryptoff,
        cryptsize,
        cryptid,
        pad,
    })
}

pub fn read_rpath_command<R: Read>(cursor: &mut R, is_little_endian: bool) -> Result<RpathCommand> {
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

    let path = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    Ok(RpathCommand { cmd, cmdsize, path })
}

pub fn read_linkedit_data_command<R: Read>(
    cursor: &mut R,
    is_little_endian: bool,
) -> Result<LinkeditDataCommand> {
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

    let dataoff = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    let datasize = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    Ok(LinkeditDataCommand {
        cmd,
        cmdsize,
        dataoff,
        datasize,
    })
}

pub fn read_thread_command<R: Read>(
    cursor: &mut R,
    is_little_endian: bool,
) -> Result<ThreadCommand> {
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

    // Read the thread state data (everything after cmd and cmdsize)
    let thread_state_size = cmdsize.saturating_sub(8) as usize;
    let mut thread_state = vec![0u8; thread_state_size];
    cursor.read_exact(&mut thread_state)?;

    Ok(ThreadCommand {
        cmd,
        cmdsize,
        thread_state,
    })
}

pub fn read_dylinker_command<R: Read>(
    cursor: &mut R,
    is_little_endian: bool,
) -> Result<DylinkerCommand> {
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

    let name = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    Ok(DylinkerCommand { cmd, cmdsize, name })
}

pub fn read_routines_command<R: Read>(
    cursor: &mut R,
    is_little_endian: bool,
) -> Result<RoutinesCommand> {
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

    let init_address = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    let init_module = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    let reserved1 = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    let reserved2 = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    let reserved3 = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    let reserved4 = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    let reserved5 = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    let reserved6 = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    Ok(RoutinesCommand {
        cmd,
        cmdsize,
        init_address,
        init_module,
        reserved1,
        reserved2,
        reserved3,
        reserved4,
        reserved5,
        reserved6,
    })
}

pub fn read_routines_command_64<R: Read>(
    cursor: &mut R,
    is_little_endian: bool,
) -> Result<RoutinesCommand64> {
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

    let init_address = if is_little_endian {
        cursor.read_u64::<LittleEndian>()?
    } else {
        cursor.read_u64::<BigEndian>()?
    };

    let init_module = if is_little_endian {
        cursor.read_u64::<LittleEndian>()?
    } else {
        cursor.read_u64::<BigEndian>()?
    };

    let reserved1 = if is_little_endian {
        cursor.read_u64::<LittleEndian>()?
    } else {
        cursor.read_u64::<BigEndian>()?
    };

    let reserved2 = if is_little_endian {
        cursor.read_u64::<LittleEndian>()?
    } else {
        cursor.read_u64::<BigEndian>()?
    };

    let reserved3 = if is_little_endian {
        cursor.read_u64::<LittleEndian>()?
    } else {
        cursor.read_u64::<BigEndian>()?
    };

    let reserved4 = if is_little_endian {
        cursor.read_u64::<LittleEndian>()?
    } else {
        cursor.read_u64::<BigEndian>()?
    };

    let reserved5 = if is_little_endian {
        cursor.read_u64::<LittleEndian>()?
    } else {
        cursor.read_u64::<BigEndian>()?
    };

    let reserved6 = if is_little_endian {
        cursor.read_u64::<LittleEndian>()?
    } else {
        cursor.read_u64::<BigEndian>()?
    };

    Ok(RoutinesCommand64 {
        cmd,
        cmdsize,
        init_address,
        init_module,
        reserved1,
        reserved2,
        reserved3,
        reserved4,
        reserved5,
        reserved6,
    })
}

pub fn read_sub_framework_command<R: Read>(
    cursor: &mut R,
    is_little_endian: bool,
) -> Result<SubFrameworkCommand> {
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

    let umbrella = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    Ok(SubFrameworkCommand {
        cmd,
        cmdsize,
        umbrella,
    })
}

pub fn read_sub_client_command<R: Read>(
    cursor: &mut R,
    is_little_endian: bool,
) -> Result<SubClientCommand> {
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

    let client = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    Ok(SubClientCommand {
        cmd,
        cmdsize,
        client,
    })
}

pub fn read_sub_library_command<R: Read>(
    cursor: &mut R,
    is_little_endian: bool,
) -> Result<SubLibraryCommand> {
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

    let sub_library = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    Ok(SubLibraryCommand {
        cmd,
        cmdsize,
        sub_library,
    })
}

pub fn read_sub_umbrella_command<R: Read>(
    cursor: &mut R,
    is_little_endian: bool,
) -> Result<SubUmbrellaCommand> {
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

    let sub_umbrella = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    Ok(SubUmbrellaCommand {
        cmd,
        cmdsize,
        sub_umbrella,
    })
}

pub fn read_prebound_dylib_command<R: Read>(
    cursor: &mut R,
    is_little_endian: bool,
) -> Result<PreboundDylibCommand> {
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

    let name = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    let nmodules = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    let linked_modules = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    Ok(PreboundDylibCommand {
        cmd,
        cmdsize,
        name,
        nmodules,
        linked_modules,
    })
}

pub fn read_twolevel_hints_command<R: Read>(
    cursor: &mut R,
    is_little_endian: bool,
) -> Result<TwoLevelHintsCommand> {
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

    let offset = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    let nhints = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    Ok(TwoLevelHintsCommand {
        cmd,
        cmdsize,
        offset,
        nhints,
    })
}

pub fn read_prebind_cksum_command<R: Read>(
    cursor: &mut R,
    is_little_endian: bool,
) -> Result<PrebindCksumCommand> {
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

    let cksum = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    Ok(PrebindCksumCommand {
        cmd,
        cmdsize,
        cksum,
    })
}

pub fn read_linker_option_command<R: Read>(
    cursor: &mut R,
    is_little_endian: bool,
) -> Result<LinkerOptionCommand> {
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

    let count = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    Ok(LinkerOptionCommand {
        cmd,
        cmdsize,
        count,
    })
}

pub fn read_note_command<R: Read>(cursor: &mut R, is_little_endian: bool) -> Result<NoteCommand> {
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

    let mut data_owner = [0u8; 16];
    cursor.read_exact(&mut data_owner)?;

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

    Ok(NoteCommand {
        cmd,
        cmdsize,
        data_owner,
        offset,
        size,
    })
}

pub fn read_fileset_entry_command<R: Read>(
    cursor: &mut R,
    is_little_endian: bool,
) -> Result<FilesetEntryCommand> {
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

    let vmaddr = if is_little_endian {
        cursor.read_u64::<LittleEndian>()?
    } else {
        cursor.read_u64::<BigEndian>()?
    };

    let fileoff = if is_little_endian {
        cursor.read_u64::<LittleEndian>()?
    } else {
        cursor.read_u64::<BigEndian>()?
    };

    let entry_id = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    let reserved = if is_little_endian {
        cursor.read_u32::<LittleEndian>()?
    } else {
        cursor.read_u32::<BigEndian>()?
    };

    Ok(FilesetEntryCommand {
        cmd,
        cmdsize,
        vmaddr,
        fileoff,
        entry_id,
        reserved,
    })
}
