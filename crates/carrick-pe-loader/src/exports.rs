//! Clean-room PE Export Directory (.edata) parsing and PeExportProvider.
//!
//! Conforms strictly to Microsoft PE and COFF Specification (Rev 11.0) Section 6.3:
//! "The .edata Section (Image Only)".

use crate::error::{ExportError, ImportError};
use crate::headers::{PeHeaders, IMAGE_DIRECTORY_ENTRY_EXPORT};
use crate::imports::{ExportProvider, ImportSymbol};
use crate::plan::VirtualAddress;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Target of an export table entry: either a direct function RVA or a forwarder string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportTarget {
    /// Function RVA relative to module base.
    Rva(u32),
    /// Forwarder string pointing to another DLL and symbol (e.g. "NTDLL.RtlExitUserProcess").
    Forwarder(String),
}

/// A single exported symbol from a PE image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportEntry {
    /// Exported function name, or `None` if exported solely by ordinal.
    pub name: Option<String>,
    /// Export ordinal number (`ordinal_base + index`).
    pub ordinal: u16,
    /// Destination: function RVA or forwarder string.
    pub target: ExportTarget,
}

/// Information parsed from a PE image's `IMAGE_EXPORT_DIRECTORY`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportDirectoryInfo {
    /// Internal ASCII DLL name recorded in the export header.
    pub dll_name: String,
    /// Starting ordinal number (typically 1).
    pub ordinal_base: u32,
    /// All exported symbols and ordinals.
    pub exports: Vec<ExportEntry>,
}

impl ExportDirectoryInfo {
    /// Finds an export entry by case-insensitive function name.
    pub fn find_by_name(&self, name: &str) -> Option<&ExportEntry> {
        self.exports.iter().find(|e| match &e.name {
            Some(n) => n.eq_ignore_ascii_case(name),
            None => false,
        })
    }

    /// Finds an export entry by ordinal number.
    pub fn find_by_ordinal(&self, ordinal: u16) -> Option<&ExportEntry> {
        self.exports.iter().find(|e| e.ordinal == ordinal)
    }
}

/// Parses the export directory table from a PE image.
///
/// Conforms to PE Specification Section 6.3: The .edata Section.
pub fn parse_export_directory(
    headers: &PeHeaders,
    file_bytes: &[u8],
) -> Result<Option<ExportDirectoryInfo>, ExportError> {
    let export_dir = match headers.data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT) {
        Some(d) if d.is_present() => d,
        _ => return Ok(None),
    };

    let dir_rva = export_dir.virtual_address;
    let dir_size = export_dir.size;

    let dir_offset = headers
        .rva_to_file_offset(dir_rva, file_bytes.len())
        .map_err(|_| ExportError::DirectoryOutOfBounds {
            rva: dir_rva,
            size: dir_size,
        })?;

    // IMAGE_EXPORT_DIRECTORY is 40 bytes (0x28)
    if dir_offset
        .checked_add(40)
        .is_none_or(|end| end > file_bytes.len())
    {
        return Err(ExportError::HeaderOutOfBounds { offset: dir_offset });
    }

    let header_bytes = &file_bytes[dir_offset..dir_offset + 40];
    let name_rva = u32::from_le_bytes(header_bytes[12..16].try_into().unwrap());
    let ordinal_base = u32::from_le_bytes(header_bytes[16..20].try_into().unwrap());
    let num_functions = u32::from_le_bytes(header_bytes[20..24].try_into().unwrap());
    let num_names = u32::from_le_bytes(header_bytes[24..28].try_into().unwrap());
    let address_table_rva = u32::from_le_bytes(header_bytes[28..32].try_into().unwrap());
    let name_pointer_rva = u32::from_le_bytes(header_bytes[32..36].try_into().unwrap());
    let ordinal_table_rva = u32::from_le_bytes(header_bytes[36..40].try_into().unwrap());

    // Read DLL name
    let dll_name_offset = headers
        .rva_to_file_offset(name_rva, file_bytes.len())
        .map_err(|_| ExportError::UnmappedRva {
            rva: name_rva,
            context: "DLL Name",
        })?;
    let mut end = dll_name_offset;
    while end < file_bytes.len() && file_bytes[end] != 0 {
        end += 1;
    }
    if end >= file_bytes.len() {
        return Err(ExportError::InvalidString {
            offset: dll_name_offset,
        });
    }
    let dll_name = String::from_utf8_lossy(&file_bytes[dll_name_offset..end]).into_owned();

    // Map Export Address Table (EAT)
    let eat_offset = headers
        .rva_to_file_offset(address_table_rva, file_bytes.len())
        .map_err(|_| ExportError::UnmappedRva {
            rva: address_table_rva,
            context: "Export Address Table",
        })?;
    let eat_bytes_len =
        (num_functions as usize)
            .checked_mul(4)
            .ok_or(ExportError::UnmappedRva {
                rva: address_table_rva,
                context: "Export Address Table size overflow",
            })?;
    if eat_offset
        .checked_add(eat_bytes_len)
        .is_none_or(|e| e > file_bytes.len())
    {
        return Err(ExportError::UnmappedRva {
            rva: address_table_rva,
            context: "Export Address Table exceeds file",
        });
    }

    // Map Name Pointer Table & Ordinal Table
    let mut name_to_ordinal_idx = BTreeMap::new();
    if num_names > 0 {
        let npt_offset = headers
            .rva_to_file_offset(name_pointer_rva, file_bytes.len())
            .map_err(|_| ExportError::UnmappedRva {
                rva: name_pointer_rva,
                context: "Name Pointer Table",
            })?;
        let ot_offset = headers
            .rva_to_file_offset(ordinal_table_rva, file_bytes.len())
            .map_err(|_| ExportError::UnmappedRva {
                rva: ordinal_table_rva,
                context: "Ordinal Table",
            })?;

        for i in 0..num_names as usize {
            let n_off = npt_offset + i * 4;
            let o_off = ot_offset + i * 2;
            if n_off + 4 > file_bytes.len() || o_off + 2 > file_bytes.len() {
                break;
            }

            let str_rva = u32::from_le_bytes(file_bytes[n_off..n_off + 4].try_into().unwrap());
            let ord_idx = u16::from_le_bytes(file_bytes[o_off..o_off + 2].try_into().unwrap());

            if let Ok(str_off) = headers.rva_to_file_offset(str_rva, file_bytes.len()) {
                let mut s_end = str_off;
                while s_end < file_bytes.len() && file_bytes[s_end] != 0 {
                    s_end += 1;
                }
                if s_end < file_bytes.len() {
                    let sym_name =
                        String::from_utf8_lossy(&file_bytes[str_off..s_end]).into_owned();
                    name_to_ordinal_idx.insert(ord_idx as usize, sym_name);
                }
            }
        }
    }

    let mut exports = Vec::with_capacity(num_functions as usize);
    for idx in 0..num_functions as usize {
        let off = eat_offset + idx * 4;
        let func_rva = u32::from_le_bytes(file_bytes[off..off + 4].try_into().unwrap());
        if func_rva == 0 {
            continue; // Empty export slot
        }

        let ordinal = (ordinal_base as usize + idx) as u16;
        let name = name_to_ordinal_idx.get(&idx).cloned();

        // Forwarder check: does func_rva lie inside the export directory?
        let target = if func_rva >= dir_rva && func_rva < dir_rva + dir_size {
            // Forwarder string
            let fwd_off = headers
                .rva_to_file_offset(func_rva, file_bytes.len())
                .map_err(|_| ExportError::UnmappedRva {
                    rva: func_rva,
                    context: "Forwarder String",
                })?;
            let mut f_end = fwd_off;
            while f_end < file_bytes.len() && file_bytes[f_end] != 0 {
                f_end += 1;
            }
            if f_end >= file_bytes.len() {
                return Err(ExportError::InvalidString { offset: fwd_off });
            }
            let fwd_str = String::from_utf8_lossy(&file_bytes[fwd_off..f_end]).into_owned();
            ExportTarget::Forwarder(fwd_str)
        } else {
            ExportTarget::Rva(func_rva)
        };

        exports.push(ExportEntry {
            name,
            ordinal,
            target,
        });
    }

    Ok(Some(ExportDirectoryInfo {
        dll_name,
        ordinal_base,
        exports,
    }))
}

/// A real PE Export Provider that resolves symbols against registered in-memory PE images.
#[derive(Debug, Clone, Default)]
pub struct PeExportProvider {
    modules: BTreeMap<String, (VirtualAddress, ExportDirectoryInfo)>,
}

impl PeExportProvider {
    /// Creates an empty PE export provider.
    pub fn new() -> Self {
        Self {
            modules: BTreeMap::new(),
        }
    }

    /// Registers a module with its base virtual address and parsed export directory.
    pub fn register_module(
        &mut self,
        dll_name: &str,
        base_va: VirtualAddress,
        info: ExportDirectoryInfo,
    ) {
        self.modules
            .insert(dll_name.to_ascii_lowercase(), (base_va, info));
    }

    /// Parses and registers a PE binary from its raw file bytes.
    pub fn register_pe_image(
        &mut self,
        dll_name: &str,
        base_va: VirtualAddress,
        headers: &PeHeaders,
        file_bytes: &[u8],
    ) -> Result<(), ExportError> {
        if let Some(info) = parse_export_directory(headers, file_bytes)? {
            self.register_module(dll_name, base_va, info);
        }
        Ok(())
    }

    /// Internal recursive resolution handling export forwarders.
    fn resolve_internal(
        &self,
        dll: &str,
        symbol: &ImportSymbol,
        depth: usize,
    ) -> Result<VirtualAddress, ImportError> {
        if depth > 16 {
            return Err(ImportError::SymbolNotFound {
                dll: dll.into(),
                symbol: "forwarder recursion limit exceeded".into(),
            });
        }

        let key = dll.to_ascii_lowercase();
        let (base_va, export_info) = self.modules.get(&key).ok_or_else(|| match symbol {
            ImportSymbol::Named(name) => ImportError::SymbolNotFound {
                dll: dll.into(),
                symbol: name.clone(),
            },
            ImportSymbol::Ordinal(ord) => ImportError::OrdinalNotFound {
                dll: dll.into(),
                ordinal: *ord,
            },
        })?;

        let entry = match symbol {
            ImportSymbol::Named(name) => {
                export_info
                    .find_by_name(name)
                    .ok_or_else(|| ImportError::SymbolNotFound {
                        dll: dll.into(),
                        symbol: name.clone(),
                    })?
            }
            ImportSymbol::Ordinal(ord) => {
                export_info
                    .find_by_ordinal(*ord)
                    .ok_or_else(|| ImportError::OrdinalNotFound {
                        dll: dll.into(),
                        ordinal: *ord,
                    })?
            }
        };

        match &entry.target {
            ExportTarget::Rva(rva) => base_va
                .checked_add(*rva as u64)
                .ok_or(ImportError::UnmappedThunkRva(*rva)),
            ExportTarget::Forwarder(fwd) => {
                // Parse "DLL.Symbol" or "DLL.#Ordinal"
                let (target_dll, target_sym) =
                    fwd.split_once('.')
                        .ok_or_else(|| ImportError::SymbolNotFound {
                            dll: dll.into(),
                            symbol: fwd.clone(),
                        })?;

                let target_dll_with_ext =
                    if target_dll.ends_with(".dll") || target_dll.ends_with(".DLL") {
                        target_dll.to_string()
                    } else {
                        alloc::format!("{target_dll}.dll")
                    };

                let target_symbol = if let Some(ord_str) = target_sym.strip_prefix('#') {
                    let ord: u16 = ord_str.parse().map_err(|_| ImportError::SymbolNotFound {
                        dll: target_dll_with_ext.clone(),
                        symbol: target_sym.into(),
                    })?;
                    ImportSymbol::Ordinal(ord)
                } else {
                    ImportSymbol::Named(target_sym.into())
                };

                self.resolve_internal(&target_dll_with_ext, &target_symbol, depth + 1)
            }
        }
    }
}

impl ExportProvider for PeExportProvider {
    fn resolve(&self, dll: &str, symbol: &ImportSymbol) -> Result<VirtualAddress, ImportError> {
        self.resolve_internal(dll, symbol, 0)
    }
}
