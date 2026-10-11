//! Clean-room PE Import Directory (.idata) resolution and pluggable ExportProvider.
//!
//! Conforms strictly to Microsoft PE and COFF Specification (Rev 11.0) Section 6.4:
//! "The .idata Section".

use crate::error::ImportError;
use crate::headers::{PeHeaders, IMAGE_DIRECTORY_ENTRY_IMPORT};
use crate::plan::{ImportBinding, VirtualAddress};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// Symbol to import: either a named function or an ordinal number.
///
/// Microsoft PE and COFF Specification (Rev 11.0) Section 6.4: Import Lookup Table.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ImportSymbol {
    /// Import by function name (e.g. "WriteFile").
    Named(String),
    /// Import by ordinal (bottom 16 bits of thunk entry when bit 63 is set).
    Ordinal(u16),
}

impl fmt::Display for ImportSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImportSymbol::Named(name) => write!(f, "{name}"),
            ImportSymbol::Ordinal(ord) => write!(f, "#{ord}"),
        }
    }
}

/// Pluggable provider that resolves DLL exports into virtual addresses.
pub trait ExportProvider {
    /// Resolves an exported symbol or ordinal from the specified DLL.
    fn resolve(&self, dll: &str, symbol: &ImportSymbol) -> Result<VirtualAddress, ImportError>;
}

/// A stub / mock export provider for host testing.
#[derive(Debug, Clone, Default)]
pub struct StubExportProvider {
    /// Map of `(dll_lower, symbol)` to virtual address.
    entries: BTreeMap<(String, ImportSymbol), VirtualAddress>,
    /// Optional synthetic base address generator for automatic mock resolution.
    synthetic_base: Option<u64>,
}

impl StubExportProvider {
    /// Creates an empty stub export provider.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            synthetic_base: None,
        }
    }

    /// Creates a stub provider that automatically synthesizes sequential addresses
    /// starting at `base` for any un-registered symbol.
    pub fn with_synthetic_fallback(base: u64) -> Self {
        Self {
            entries: BTreeMap::new(),
            synthetic_base: Some(base),
        }
    }

    /// Registers a named function export.
    pub fn add_symbol(&mut self, dll: &str, symbol: &str, va: VirtualAddress) {
        self.entries.insert(
            (dll.to_ascii_lowercase(), ImportSymbol::Named(symbol.into())),
            va,
        );
    }

    /// Registers an ordinal export.
    pub fn add_ordinal(&mut self, dll: &str, ordinal: u16, va: VirtualAddress) {
        self.entries.insert(
            (dll.to_ascii_lowercase(), ImportSymbol::Ordinal(ordinal)),
            va,
        );
    }
}

impl ExportProvider for StubExportProvider {
    fn resolve(&self, dll: &str, symbol: &ImportSymbol) -> Result<VirtualAddress, ImportError> {
        let key = (dll.to_ascii_lowercase(), symbol.clone());
        if let Some(&va) = self.entries.get(&key) {
            return Ok(va);
        }

        if let Some(base) = self.synthetic_base {
            // Hash the dll and symbol to produce a deterministic synthetic address
            let mut h = base;
            for b in dll.bytes() {
                h = h.wrapping_mul(31).wrapping_add(b as u64);
            }
            match symbol {
                ImportSymbol::Named(name) => {
                    for b in name.bytes() {
                        h = h.wrapping_mul(31).wrapping_add(b as u64);
                    }
                }
                ImportSymbol::Ordinal(ord) => {
                    h = h.wrapping_mul(31).wrapping_add(*ord as u64);
                }
            }
            // Align to 16 bytes
            let synthetic_va = VirtualAddress::new((h & 0x7FFF_FFFF_FFF0) | 0x1000);
            return Ok(synthetic_va);
        }

        match symbol {
            ImportSymbol::Named(name) => Err(ImportError::SymbolNotFound {
                dll: dll.into(),
                symbol: name.clone(),
            }),
            ImportSymbol::Ordinal(ord) => Err(ImportError::OrdinalNotFound {
                dll: dll.into(),
                ordinal: *ord,
            }),
        }
    }
}

/// The import mechanism type: standard import or delay-loaded import.
///
/// Conforms to Microsoft PE and COFF Specification (Rev 11.0) Sections 6.4 (.idata)
/// and 6.6 (Delay-Load Directory Table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ImportKind {
    /// Standard dynamic link import from .idata (IMAGE_DIRECTORY_ENTRY_IMPORT).
    Standard,
    /// Delay-loaded dynamic link import from .didat (IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT).
    DelayLoad,
}

impl fmt::Display for ImportKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImportKind::Standard => write!(f, "standard"),
            ImportKind::DelayLoad => write!(f, "delay-load"),
        }
    }
}

/// A parsed import entry without symbol resolution.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RawImport {
    /// Name of the target DLL or API set (e.g. "KERNEL32.dll" or "api-ms-win-core-synch-l1-2-0.dll").
    pub dll_name: String,
    /// Imported function name or ordinal.
    pub symbol: ImportSymbol,
    /// Import mechanism: standard or delay-load.
    pub kind: ImportKind,
    /// Optional ordinal hint from IMAGE_IMPORT_BY_NAME if imported by name.
    pub hint: Option<u16>,
    /// RVA in the IAT where the address will be loaded.
    pub iat_rva: u32,
}

/// Parses the standard import directory (.idata) without resolving symbols.
///
/// Conforms to Microsoft PE and COFF Specification (Rev 11.0) Section 6.4: The .idata Section.
pub fn parse_import_directory(
    headers: &PeHeaders,
    file_bytes: &[u8],
) -> Result<Vec<RawImport>, ImportError> {
    let import_dir = match headers.data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT) {
        Some(d) if d.is_present() && d.size > 0 => d,
        _ => return Ok(Vec::new()),
    };

    let dir_rva = import_dir.virtual_address;
    let dir_size = import_dir.size as usize;

    let dir_offset = headers
        .rva_to_file_offset(dir_rva, file_bytes.len())
        .map_err(|_| ImportError::DirectoryOutOfBounds {
            rva: dir_rva,
            size: import_dir.size,
        })?;

    if dir_offset
        .checked_add(dir_size)
        .is_none_or(|end| end > file_bytes.len())
    {
        return Err(ImportError::DirectoryOutOfBounds {
            rva: dir_rva,
            size: import_dir.size,
        });
    }

    let mut imports = Vec::new();
    let mut desc_offset = dir_offset;

    // Loop through IMAGE_IMPORT_DESCRIPTOR entries (20 bytes each)
    loop {
        if desc_offset
            .checked_add(20)
            .is_none_or(|end| end > file_bytes.len())
        {
            return Err(ImportError::DescriptorOutOfBounds {
                offset: desc_offset,
            });
        }

        let desc = &file_bytes[desc_offset..desc_offset + 20];
        // An all-zero entry marks the end of the Import Directory Table
        if desc.iter().all(|&b| b == 0) {
            break;
        }

        let original_first_thunk = u32::from_le_bytes(desc[0..4].try_into().unwrap());
        let name_rva = u32::from_le_bytes(desc[12..16].try_into().unwrap());
        let first_thunk = u32::from_le_bytes(desc[16..20].try_into().unwrap());

        if name_rva == 0 && original_first_thunk == 0 && first_thunk == 0 {
            break;
        }

        // Validate that DLL Name RVA points into a mapped section
        if headers.find_section_by_rva(name_rva).is_none() {
            return Err(ImportError::UnmappedDllNameRva(name_rva));
        }

        let dll_name_offset = headers
            .rva_to_file_offset(name_rva, file_bytes.len())
            .map_err(|_| ImportError::UnmappedDllNameRva(name_rva))?;

        // Read null-terminated DLL name
        let mut end = dll_name_offset;
        while end < file_bytes.len() && file_bytes[end] != 0 {
            end += 1;
        }
        if end >= file_bytes.len() {
            return Err(ImportError::InvalidDllName(dll_name_offset));
        }
        let dll_name = String::from_utf8_lossy(&file_bytes[dll_name_offset..end]).into_owned();

        // Use OriginalFirstThunk (ILT) if non-zero, otherwise FirstThunk (IAT)
        let thunk_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };

        if headers.find_section_by_rva(thunk_rva).is_none() {
            return Err(ImportError::UnmappedThunkRva(thunk_rva));
        }

        let mut thunk_offset = headers
            .rva_to_file_offset(thunk_rva, file_bytes.len())
            .map_err(|_| ImportError::UnmappedThunkRva(thunk_rva))?;

        let mut entry_index = 0u32;

        loop {
            if thunk_offset + 8 > file_bytes.len() {
                break;
            }

            let thunk_entry = u64::from_le_bytes(
                file_bytes[thunk_offset..thunk_offset + 8]
                    .try_into()
                    .unwrap(),
            );
            if thunk_entry == 0 {
                break;
            }

            let (symbol, hint) = if (thunk_entry & 0x8000_0000_0000_0000) != 0 {
                // Bit 63 is set: import by ordinal
                let ordinal = (thunk_entry & 0xFFFF) as u16;
                (ImportSymbol::Ordinal(ordinal), None)
            } else {
                // Bit 63 is clear: import by name (RVA points to IMAGE_IMPORT_BY_NAME)
                let ibn_rva = (thunk_entry & 0x7FFF_FFFF) as u32;

                // Validate that ibn_rva points inside a mapped section
                if headers.find_section_by_rva(ibn_rva).is_none() {
                    return Err(ImportError::UnmappedImportByNameRva(ibn_rva));
                }

                let ibn_offset = headers
                    .rva_to_file_offset(ibn_rva, file_bytes.len())
                    .map_err(|_| ImportError::UnmappedImportByNameRva(ibn_rva))?;

                // IMAGE_IMPORT_BY_NAME: 2 bytes hint + ASCII name null-terminated
                if ibn_offset + 2 >= file_bytes.len() {
                    return Err(ImportError::UnmappedImportByNameRva(ibn_rva));
                }

                let parsed_hint =
                    u16::from_le_bytes(file_bytes[ibn_offset..ibn_offset + 2].try_into().unwrap());

                let name_start = ibn_offset + 2;
                let mut name_end = name_start;
                while name_end < file_bytes.len() && file_bytes[name_end] != 0 {
                    name_end += 1;
                }
                if name_end >= file_bytes.len() {
                    return Err(ImportError::UnmappedImportByNameRva(ibn_rva));
                }

                let sym_name =
                    String::from_utf8_lossy(&file_bytes[name_start..name_end]).into_owned();
                (ImportSymbol::Named(sym_name), Some(parsed_hint))
            };

            let iat_rva = first_thunk
                .checked_add(
                    entry_index
                        .checked_mul(8)
                        .ok_or(ImportError::UnmappedThunkRva(first_thunk))?,
                )
                .ok_or(ImportError::UnmappedThunkRva(first_thunk))?;

            imports.push(RawImport {
                dll_name: dll_name.clone(),
                symbol,
                kind: ImportKind::Standard,
                hint,
                iat_rva,
            });

            thunk_offset += 8;
            entry_index += 1;
        }

        desc_offset += 20;
    }

    Ok(imports)
}

/// Parses the delay-load import directory (.didat) without resolving symbols.
///
/// Conforms strictly to Microsoft PE and COFF Specification (Rev 11.0) Section 6.6:
/// "The Delay-Load Directory Table (Image Only)".
pub fn parse_delay_import_directory(
    headers: &PeHeaders,
    file_bytes: &[u8],
) -> Result<Vec<RawImport>, ImportError> {
    use crate::headers::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT;

    let delay_dir = match headers.data_directory(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) {
        Some(d) if d.is_present() && d.size > 0 => d,
        _ => return Ok(Vec::new()),
    };

    let dir_rva = delay_dir.virtual_address;
    let dir_size = delay_dir.size as usize;

    let dir_offset = headers
        .rva_to_file_offset(dir_rva, file_bytes.len())
        .map_err(|_| ImportError::DirectoryOutOfBounds {
            rva: dir_rva,
            size: delay_dir.size,
        })?;

    if dir_offset
        .checked_add(dir_size)
        .is_none_or(|end| end > file_bytes.len())
    {
        return Err(ImportError::DirectoryOutOfBounds {
            rva: dir_rva,
            size: delay_dir.size,
        });
    }

    let mut imports = Vec::new();
    let mut desc_offset = dir_offset;

    // Loop through IMAGE_DELAYLOAD_DESCRIPTOR entries (32 bytes each)
    loop {
        if desc_offset
            .checked_add(32)
            .is_none_or(|end| end > file_bytes.len())
        {
            break;
        }

        let desc = &file_bytes[desc_offset..desc_offset + 32];
        // Terminated by an all-zero descriptor
        if desc.iter().all(|&b| b == 0) {
            break;
        }

        let dll_name_rva = u32::from_le_bytes(desc[4..8].try_into().unwrap());
        let iat_rva_base = u32::from_le_bytes(desc[12..16].try_into().unwrap());
        let int_rva = u32::from_le_bytes(desc[16..20].try_into().unwrap());

        if dll_name_rva == 0 {
            break;
        }

        // Validate DLL Name RVA
        if headers.find_section_by_rva(dll_name_rva).is_none() {
            return Err(ImportError::UnmappedDllNameRva(dll_name_rva));
        }

        let dll_name_offset = headers
            .rva_to_file_offset(dll_name_rva, file_bytes.len())
            .map_err(|_| ImportError::UnmappedDllNameRva(dll_name_rva))?;

        let mut end = dll_name_offset;
        while end < file_bytes.len() && file_bytes[end] != 0 {
            end += 1;
        }
        if end >= file_bytes.len() {
            return Err(ImportError::InvalidDllName(dll_name_offset));
        }
        let dll_name = String::from_utf8_lossy(&file_bytes[dll_name_offset..end]).into_owned();

        // Use ImportNameTable (INT) if present, fallback to ImportAddressTable (IAT)
        let thunk_rva = if int_rva != 0 { int_rva } else { iat_rva_base };

        if thunk_rva != 0 {
            if headers.find_section_by_rva(thunk_rva).is_none() {
                return Err(ImportError::UnmappedThunkRva(thunk_rva));
            }

            let mut thunk_offset = headers
                .rva_to_file_offset(thunk_rva, file_bytes.len())
                .map_err(|_| ImportError::UnmappedThunkRva(thunk_rva))?;

            let mut entry_index = 0u32;

            loop {
                if thunk_offset + 8 > file_bytes.len() {
                    break;
                }

                let thunk_entry = u64::from_le_bytes(
                    file_bytes[thunk_offset..thunk_offset + 8]
                        .try_into()
                        .unwrap(),
                );
                if thunk_entry == 0 {
                    break;
                }

                let (symbol, hint) = if (thunk_entry & 0x8000_0000_0000_0000) != 0 {
                    let ordinal = (thunk_entry & 0xFFFF) as u16;
                    (ImportSymbol::Ordinal(ordinal), None)
                } else {
                    let ibn_rva = (thunk_entry & 0x7FFF_FFFF) as u32;

                    if headers.find_section_by_rva(ibn_rva).is_none() {
                        return Err(ImportError::UnmappedImportByNameRva(ibn_rva));
                    }

                    let ibn_offset = headers
                        .rva_to_file_offset(ibn_rva, file_bytes.len())
                        .map_err(|_| ImportError::UnmappedImportByNameRva(ibn_rva))?;

                    if ibn_offset + 2 >= file_bytes.len() {
                        return Err(ImportError::UnmappedImportByNameRva(ibn_rva));
                    }

                    let parsed_hint = u16::from_le_bytes(
                        file_bytes[ibn_offset..ibn_offset + 2].try_into().unwrap(),
                    );

                    let name_start = ibn_offset + 2;
                    let mut name_end = name_start;
                    while name_end < file_bytes.len() && file_bytes[name_end] != 0 {
                        name_end += 1;
                    }
                    if name_end >= file_bytes.len() {
                        return Err(ImportError::UnmappedImportByNameRva(ibn_rva));
                    }

                    let sym_name =
                        String::from_utf8_lossy(&file_bytes[name_start..name_end]).into_owned();
                    (ImportSymbol::Named(sym_name), Some(parsed_hint))
                };

                let iat_rva = if iat_rva_base != 0 {
                    iat_rva_base.wrapping_add(entry_index.wrapping_mul(8))
                } else {
                    0
                };

                imports.push(RawImport {
                    dll_name: dll_name.clone(),
                    symbol,
                    kind: ImportKind::DelayLoad,
                    hint,
                    iat_rva,
                });

                thunk_offset += 8;
                entry_index += 1;
            }
        }

        desc_offset += 32;
    }

    Ok(imports)
}

/// Parses both standard and delay-load imports from the PE file.
pub fn parse_all_imports(
    headers: &PeHeaders,
    file_bytes: &[u8],
) -> Result<Vec<RawImport>, ImportError> {
    let mut all = parse_import_directory(headers, file_bytes)?;
    let mut delay = parse_delay_import_directory(headers, file_bytes)?;
    all.append(&mut delay);
    Ok(all)
}

/// Parses the import directory table and resolves all symbols via the ExportProvider.
///
/// Conforms to Microsoft PE and COFF Specification (Rev 11.0) Section 6.4: The .idata Section.
pub fn parse_and_resolve_imports<P: ExportProvider>(
    headers: &PeHeaders,
    file_bytes: &[u8],
    actual_base: VirtualAddress,
    provider: &P,
) -> Result<Vec<ImportBinding>, ImportError> {
    let raw_imports = parse_import_directory(headers, file_bytes)?;
    let mut bindings = Vec::with_capacity(raw_imports.len());

    for raw in raw_imports {
        let resolved_va = provider.resolve(&raw.dll_name, &raw.symbol)?;
        let iat_va = actual_base
            .checked_add(raw.iat_rva as u64)
            .ok_or(ImportError::UnmappedThunkRva(raw.iat_rva))?;

        bindings.push(ImportBinding {
            dll_name: raw.dll_name,
            symbol: raw.symbol,
            iat_rva: raw.iat_rva,
            iat_va,
            resolved_va,
        });
    }

    Ok(bindings)
}
