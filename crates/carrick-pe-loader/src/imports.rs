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

/// Parses the import directory table and resolves all symbols via the ExportProvider.
///
/// Conforms to Microsoft PE and COFF Specification (Rev 11.0) Section 6.4: The .idata Section.
pub fn parse_and_resolve_imports<P: ExportProvider>(
    headers: &PeHeaders,
    file_bytes: &[u8],
    actual_base: VirtualAddress,
    provider: &P,
) -> Result<Vec<ImportBinding>, ImportError> {
    let import_dir = match headers.data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT) {
        Some(d) if d.is_present() => d,
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

    let mut bindings = Vec::new();
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

            let symbol = if (thunk_entry & 0x8000_0000_0000_0000) != 0 {
                // Bit 63 is set: import by ordinal
                let ordinal = (thunk_entry & 0xFFFF) as u16;
                ImportSymbol::Ordinal(ordinal)
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
                ImportSymbol::Named(sym_name)
            };

            // Resolve symbol via ExportProvider
            let resolved_va = provider.resolve(&dll_name, &symbol)?;

            // IAT slot RVA and VA
            let iat_rva = first_thunk
                .checked_add(
                    entry_index
                        .checked_mul(8)
                        .ok_or(ImportError::UnmappedThunkRva(first_thunk))?,
                )
                .ok_or(ImportError::UnmappedThunkRva(first_thunk))?;

            let iat_va = actual_base
                .checked_add(iat_rva as u64)
                .ok_or(ImportError::UnmappedThunkRva(iat_rva))?;

            bindings.push(ImportBinding {
                dll_name: dll_name.clone(),
                symbol,
                iat_rva,
                iat_va,
                resolved_va,
            });

            thunk_offset += 8;
            entry_index += 1;
        }

        desc_offset += 20;
    }

    Ok(bindings)
}
