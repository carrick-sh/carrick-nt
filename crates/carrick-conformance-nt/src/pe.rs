//! Clean-room PE32+ parser and validator.
//!
//! Conforms strictly to the Microsoft PE and COFF Specification (Rev 11.0).
//! Used to verify machine architecture, subsystem, and imported symbols of
//! test executables without proprietary SDKs or emulator tooling.

use std::collections::BTreeMap;
use thiserror::Error;

pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_OPTIONAL_HEADER_MAGIC_PE32_PLUS: u16 = 0x020B;
pub const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PeParseError {
    #[error("File is too small to contain a valid PE header (length: {0})")]
    FileTooSmall(usize),
    #[error("Invalid DOS signature (expected 'MZ', got {0:#06x})")]
    InvalidDosSignature(u16),
    #[error("Invalid PE signature offset (e_lfanew: {0:#x})")]
    InvalidPeOffset(usize),
    #[error("Invalid PE signature (expected 'PE\\0\\0', got {0:?})")]
    InvalidPeSignature([u8; 4]),
    #[error("Unsupported machine architecture (expected AMD64 0x8664, got {0:#06x})")]
    UnsupportedMachine(u16),
    #[error("Unsupported optional header magic (expected PE32+ 0x020B, got {0:#06x})")]
    UnsupportedOptionalHeaderMagic(u16),
    #[error("Corrupt section table at offset {0}")]
    CorruptSectionTable(usize),
    #[error("RVA {0:#x} could not be resolved to a file offset in any section")]
    UnmappedRva(u32),
    #[error("String at offset {0} is not valid ASCII or exceeds buffer")]
    InvalidString(usize),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PeVerificationError {
    #[error("Parse error: {0}")]
    Parse(#[from] PeParseError),
    #[error("Subsystem mismatch: expected Windows CUI (3), got {0}")]
    SubsystemMismatch(u16),
    #[error("Unexpected imported DLLs: expected only KERNEL32.dll, found {0:?}")]
    UnexpectedImports(Vec<String>),
    #[error("Missing expected imported symbol: {0}")]
    MissingImportedSymbol(String),
    #[error("Unexpected imported symbol: {0}")]
    UnexpectedImportedSymbol(String),
}

/// Parsed section header information.
#[derive(Debug, Clone)]
pub struct SectionHeader {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
}

/// Key metadata parsed from a PE32+ binary.
#[derive(Debug, Clone)]
pub struct PeImageInfo {
    pub machine: u16,
    pub number_of_sections: u16,
    pub entry_point_rva: u32,
    pub image_base: u64,
    pub subsystem: u16,
    pub sections: Vec<SectionHeader>,
    /// Map of imported DLL name (lowercase) to list of imported symbol names.
    pub imports: BTreeMap<String, Vec<String>>,
}

/// Parses and extracts PE32+ metadata from raw binary bytes.
pub fn parse_pe(bytes: &[u8]) -> Result<PeImageInfo, PeParseError> {
    if bytes.len() < 0x40 {
        return Err(PeParseError::FileTooSmall(bytes.len()));
    }

    // 1. DOS Header: check e_magic ('MZ' = 0x5A4D)
    let dos_magic = u16::from_le_bytes([bytes[0], bytes[1]]);
    if dos_magic != 0x5A4D {
        return Err(PeParseError::InvalidDosSignature(dos_magic));
    }

    // e_lfanew at offset 0x3C (60)
    let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    if e_lfanew + 4 + 20 > bytes.len() {
        return Err(PeParseError::InvalidPeOffset(e_lfanew));
    }

    // 2. PE Signature: 'PE\0\0' = [0x50, 0x45, 0x00, 0x00]
    let pe_sig = &bytes[e_lfanew..e_lfanew + 4];
    if pe_sig != b"PE\0\0" {
        return Err(PeParseError::InvalidPeSignature([
            pe_sig[0], pe_sig[1], pe_sig[2], pe_sig[3],
        ]));
    }

    // 3. COFF File Header (20 bytes)
    let coff_offset = e_lfanew + 4;
    let machine = u16::from_le_bytes(bytes[coff_offset..coff_offset + 2].try_into().unwrap());
    let number_of_sections =
        u16::from_le_bytes(bytes[coff_offset + 2..coff_offset + 4].try_into().unwrap());
    let size_of_optional_header = u16::from_le_bytes(
        bytes[coff_offset + 16..coff_offset + 18]
            .try_into()
            .unwrap(),
    ) as usize;

    if machine != IMAGE_FILE_MACHINE_AMD64 {
        return Err(PeParseError::UnsupportedMachine(machine));
    }

    // 4. Optional Header (PE32+)
    let opt_offset = coff_offset + 20;
    if opt_offset + size_of_optional_header > bytes.len() || size_of_optional_header < 112 {
        return Err(PeParseError::FileTooSmall(bytes.len()));
    }

    let magic = u16::from_le_bytes(bytes[opt_offset..opt_offset + 2].try_into().unwrap());
    if magic != IMAGE_OPTIONAL_HEADER_MAGIC_PE32_PLUS {
        return Err(PeParseError::UnsupportedOptionalHeaderMagic(magic));
    }

    let entry_point_rva =
        u32::from_le_bytes(bytes[opt_offset + 16..opt_offset + 20].try_into().unwrap());
    let image_base =
        u64::from_le_bytes(bytes[opt_offset + 24..opt_offset + 32].try_into().unwrap());
    let subsystem = u16::from_le_bytes(bytes[opt_offset + 68..opt_offset + 70].try_into().unwrap());

    // Import Directory: DataDirectory[1] at opt_offset + 120 (RVA: 4 bytes, Size: 4 bytes)
    let import_table_rva = if size_of_optional_header >= 128 {
        u32::from_le_bytes(
            bytes[opt_offset + 120..opt_offset + 124]
                .try_into()
                .unwrap(),
        )
    } else {
        0
    };
    let import_table_size = if size_of_optional_header >= 128 {
        u32::from_le_bytes(
            bytes[opt_offset + 124..opt_offset + 128]
                .try_into()
                .unwrap(),
        )
    } else {
        0
    };

    // 5. Section Headers (40 bytes each)
    let section_table_offset = opt_offset + size_of_optional_header;
    let mut sections = Vec::with_capacity(number_of_sections as usize);

    for i in 0..number_of_sections as usize {
        let sec_offset = section_table_offset + i * 40;
        if sec_offset + 40 > bytes.len() {
            return Err(PeParseError::CorruptSectionTable(sec_offset));
        }

        let name_raw = &bytes[sec_offset..sec_offset + 8];
        let name_end = name_raw.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&name_raw[..name_end]).into_owned();

        let virtual_size =
            u32::from_le_bytes(bytes[sec_offset + 8..sec_offset + 12].try_into().unwrap());
        let virtual_address =
            u32::from_le_bytes(bytes[sec_offset + 12..sec_offset + 16].try_into().unwrap());
        let size_of_raw_data =
            u32::from_le_bytes(bytes[sec_offset + 16..sec_offset + 20].try_into().unwrap());
        let pointer_to_raw_data =
            u32::from_le_bytes(bytes[sec_offset + 20..sec_offset + 24].try_into().unwrap());
        let characteristics =
            u32::from_le_bytes(bytes[sec_offset + 36..sec_offset + 40].try_into().unwrap());

        sections.push(SectionHeader {
            name,
            virtual_size,
            virtual_address,
            size_of_raw_data,
            pointer_to_raw_data,
            characteristics,
        });
    }

    // Helper: resolve RVA to file offset
    let rva_to_offset = |rva: u32| -> Result<usize, PeParseError> {
        for sec in &sections {
            let span = sec.virtual_size.max(sec.size_of_raw_data);
            if rva >= sec.virtual_address && rva < sec.virtual_address + span {
                let offset =
                    sec.pointer_to_raw_data as usize + (rva - sec.virtual_address) as usize;
                if offset <= bytes.len() {
                    return Ok(offset);
                }
            }
        }
        Err(PeParseError::UnmappedRva(rva))
    };

    // Helper: read null-terminated ASCII string from RVA
    let read_ascii_string = |rva: u32| -> Result<String, PeParseError> {
        let offset = rva_to_offset(rva)?;
        let mut end = offset;
        while end < bytes.len() && bytes[end] != 0 {
            end += 1;
        }
        if end >= bytes.len() {
            return Err(PeParseError::InvalidString(offset));
        }
        Ok(String::from_utf8_lossy(&bytes[offset..end]).into_owned())
    };

    // 6. Parse Imports
    let mut imports: BTreeMap<String, Vec<String>> = BTreeMap::new();

    if import_table_rva != 0 && import_table_size != 0 {
        let mut desc_offset = rva_to_offset(import_table_rva)?;

        loop {
            if desc_offset + 20 > bytes.len() {
                break;
            }

            let descriptor = &bytes[desc_offset..desc_offset + 20];
            // An all-zero entry marks the end of the array
            if descriptor.iter().all(|&b| b == 0) {
                break;
            }

            let original_first_thunk = u32::from_le_bytes(descriptor[0..4].try_into().unwrap());
            let name_rva = u32::from_le_bytes(descriptor[12..16].try_into().unwrap());
            let first_thunk = u32::from_le_bytes(descriptor[16..20].try_into().unwrap());

            let dll_name = read_ascii_string(name_rva)?;
            let thunk_rva = if original_first_thunk != 0 {
                original_first_thunk
            } else {
                first_thunk
            };

            let mut thunk_offset = rva_to_offset(thunk_rva)?;
            let mut symbols = Vec::new();

            loop {
                if thunk_offset + 8 > bytes.len() {
                    break;
                }
                let thunk_entry =
                    u64::from_le_bytes(bytes[thunk_offset..thunk_offset + 8].try_into().unwrap());
                if thunk_entry == 0 {
                    break;
                }

                // Bit 63 indicates import by ordinal
                if (thunk_entry & 0x8000_0000_0000_0000) != 0 {
                    let ordinal = (thunk_entry & 0xFFFF) as u16;
                    symbols.push(format!("Ordinal#{ordinal}"));
                } else {
                    let ibn_rva = (thunk_entry & 0x7FFF_FFFF) as u32;
                    let ibn_offset = rva_to_offset(ibn_rva)?;
                    if ibn_offset + 2 < bytes.len() {
                        // Skip 2-byte Hint, read null-terminated symbol name
                        let mut name_end = ibn_offset + 2;
                        while name_end < bytes.len() && bytes[name_end] != 0 {
                            name_end += 1;
                        }
                        let sym_name =
                            String::from_utf8_lossy(&bytes[ibn_offset + 2..name_end]).into_owned();
                        symbols.push(sym_name);
                    }
                }

                thunk_offset += 8;
            }

            imports.insert(dll_name.to_lowercase(), symbols);
            desc_offset += 20;
        }
    }

    Ok(PeImageInfo {
        machine,
        number_of_sections,
        entry_point_rva,
        image_base,
        subsystem,
        sections,
        imports,
    })
}

/// Verifies that a binary satisfies all M0 console hello acceptance criteria:
/// - Architecture is AMD64 (x86_64)
/// - Subsystem is Windows CUI (console)
/// - Imported DLLs are strictly restricted to `KERNEL32.dll`
/// - Imported symbols include exactly `GetStdHandle`, `WriteFile`, `ExitProcess`
pub fn verify_hello_console_pe(bytes: &[u8]) -> Result<PeImageInfo, PeVerificationError> {
    verify_fixture_pe(bytes, &["ExitProcess", "GetStdHandle", "WriteFile"])
}

/// Verifies that a binary satisfies all clean-room echo_cmdline_env acceptance criteria:
/// - Architecture is AMD64 (x86_64)
/// - Subsystem is Windows CUI (console)
/// - Imported DLLs are strictly restricted to `KERNEL32.dll`
/// - Imported symbols include exactly `ExitProcess`, `GetCommandLineW`, `GetEnvironmentVariableW`, `GetStdHandle`, `WriteFile`
pub fn verify_echo_cmdline_env_pe(bytes: &[u8]) -> Result<PeImageInfo, PeVerificationError> {
    let expected_symbols = [
        "ExitProcess",
        "GetCommandLineW",
        "GetEnvironmentVariableW",
        "GetStdHandle",
        "WriteFile",
    ];
    verify_fixture_pe(bytes, &expected_symbols)
}

/// Generic helper to verify a clean-room console fixture PE binary against expected imports.
pub fn verify_fixture_pe(
    bytes: &[u8],
    expected_symbols: &[&str],
) -> Result<PeImageInfo, PeVerificationError> {
    let info = parse_pe(bytes)?;

    if info.subsystem != IMAGE_SUBSYSTEM_WINDOWS_CUI {
        return Err(PeVerificationError::SubsystemMismatch(info.subsystem));
    }

    let dll_keys: Vec<String> = info.imports.keys().cloned().collect();
    let expected_dll = "kernel32.dll";

    if dll_keys.len() != 1 || dll_keys[0] != expected_dll {
        return Err(PeVerificationError::UnexpectedImports(dll_keys));
    }

    let symbols = &info.imports[expected_dll];

    for &sym in expected_symbols {
        if !symbols.iter().any(|s| s == sym) {
            return Err(PeVerificationError::MissingImportedSymbol(sym.to_string()));
        }
    }

    for sym in symbols {
        if !expected_symbols.contains(&sym.as_str()) {
            return Err(PeVerificationError::UnexpectedImportedSymbol(sym.clone()));
        }
    }

    Ok(info)
}
