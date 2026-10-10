//! Clean-room Thread Local Storage (.tls) Directory parser.
//!
//! Conforms strictly to Microsoft PE and COFF Specification (Rev 11.0) Section 6.7:
//! "The .tls Section (Image Only)".

use crate::error::TlsError;
use crate::headers::{PeHeaders, IMAGE_DIRECTORY_ENTRY_TLS};
use crate::plan::{VirtualAddress, VirtualRange};
use alloc::vec::Vec;

/// Parsed information from `IMAGE_TLS_DIRECTORY64`.
/// Microsoft PE and COFF Specification (Rev 11.0) Section 6.7.1: The TLS Directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsDirectoryInfo {
    /// Range of template raw data `[start_address, end_address)`.
    pub raw_data_range: VirtualRange,
    /// Location where the loader writes the TLS index assigned to this image.
    pub index_va: VirtualAddress,
    /// Address of null-terminated array of TLS callback function pointers.
    pub callbacks_va: VirtualAddress,
    /// Parsed array of TLS callback virtual addresses.
    pub callbacks: Vec<VirtualAddress>,
    /// Size in bytes of zero-fill beyond the raw data.
    pub size_of_zero_fill: u32,
    /// Reserved characteristics flags.
    pub characteristics: u32,
}

/// Parses the TLS directory table if present in the image.
pub fn parse_tls_directory(
    headers: &PeHeaders,
    file_bytes: &[u8],
) -> Result<Option<TlsDirectoryInfo>, TlsError> {
    let tls_dir = match headers.data_directory(IMAGE_DIRECTORY_ENTRY_TLS) {
        Some(d) if d.is_present() => d,
        _ => return Ok(None),
    };

    let dir_rva = tls_dir.virtual_address;
    let dir_size = tls_dir.size as usize;

    if dir_size < 40 {
        return Err(TlsError::DirectoryTooSmall {
            expected: 40,
            actual: dir_size,
        });
    }

    let dir_offset = headers
        .rva_to_file_offset(dir_rva, file_bytes.len())
        .map_err(|_| TlsError::DirectoryOutOfBounds {
            rva: dir_rva,
            size: tls_dir.size,
        })?;

    if dir_offset
        .checked_add(40)
        .is_none_or(|end| end > file_bytes.len())
    {
        return Err(TlsError::DirectoryOutOfBounds {
            rva: dir_rva,
            size: tls_dir.size,
        });
    }

    let raw = &file_bytes[dir_offset..dir_offset + 40];
    let start_raw_data = u64::from_le_bytes(raw[0..8].try_into().unwrap());
    let end_raw_data = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    let address_of_index = u64::from_le_bytes(raw[16..24].try_into().unwrap());
    let address_of_callbacks = u64::from_le_bytes(raw[24..32].try_into().unwrap());
    let size_of_zero_fill = u32::from_le_bytes(raw[32..36].try_into().unwrap());
    let characteristics = u32::from_le_bytes(raw[36..40].try_into().unwrap());

    if start_raw_data > end_raw_data {
        return Err(TlsError::InvalidRawDataRange {
            start: start_raw_data,
            end: end_raw_data,
        });
    }

    let raw_data_range = VirtualRange {
        start: VirtualAddress::new(start_raw_data),
        end: VirtualAddress::new(end_raw_data),
    };

    let mut callbacks = Vec::new();
    let preferred_base = headers.optional.image_base;

    if address_of_callbacks != 0 {
        // If the callbacks address falls inside preferred image base
        if address_of_callbacks >= preferred_base {
            let cb_rva = (address_of_callbacks - preferred_base) as u32;
            if let Ok(mut cb_off) = headers.rva_to_file_offset(cb_rva, file_bytes.len()) {
                while cb_off + 8 <= file_bytes.len() {
                    let fn_ptr =
                        u64::from_le_bytes(file_bytes[cb_off..cb_off + 8].try_into().unwrap());
                    if fn_ptr == 0 {
                        break;
                    }
                    callbacks.push(VirtualAddress::new(fn_ptr));
                    cb_off += 8;
                }
            }
        }
    }

    Ok(Some(TlsDirectoryInfo {
        raw_data_range,
        index_va: VirtualAddress::new(address_of_index),
        callbacks_va: VirtualAddress::new(address_of_callbacks),
        callbacks,
        size_of_zero_fill,
        characteristics,
    }))
}
