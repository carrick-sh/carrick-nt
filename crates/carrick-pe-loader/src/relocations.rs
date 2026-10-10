//! Clean-room PE Base Relocation (.reloc) Engine.
//!
//! Conforms strictly to Microsoft PE and COFF Specification (Rev 11.0) Section 6.6:
//! "The .reloc Section (Image Only)".

use crate::error::RelocationError;
use crate::headers::{PeHeaders, IMAGE_DIRECTORY_ENTRY_BASERELOC};
use crate::plan::{RelocationDelta, VirtualAddress};
use alloc::vec::Vec;

/// Base relocation type flags.
/// Microsoft PE and COFF Specification (Rev 11.0) Section 6.6.2: Base Relocation Types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationType {
    /// IMAGE_REL_BASED_ABSOLUTE (0): The relocation is skipped. Used for padding.
    Absolute,
    /// IMAGE_REL_BASED_HIGH (1): High 16 bits of 32-bit field.
    High,
    /// IMAGE_REL_BASED_LOW (2): Low 16 bits of 32-bit field.
    Low,
    /// IMAGE_REL_BASED_HIGHLOW (3): 32-bit full fixup.
    HighLow,
    /// IMAGE_REL_BASED_HIGHADJ (4): High 16 bits with sign adjustment.
    HighAdj,
    /// IMAGE_REL_BASED_DIR64 (10): 64-bit address fixup for PE32+.
    Dir64,
    /// Any other or unrecognized relocation type.
    Unsupported(u8),
}

impl RelocationType {
    /// Parses a 4-bit type nibble into a RelocationType enum.
    pub fn from_nibble(nibble: u8) -> Self {
        match nibble {
            0 => RelocationType::Absolute,
            1 => RelocationType::High,
            2 => RelocationType::Low,
            3 => RelocationType::HighLow,
            4 => RelocationType::HighAdj,
            10 => RelocationType::Dir64,
            other => RelocationType::Unsupported(other),
        }
    }
}

/// A parsed base relocation block for a single 4 KiB page.
/// Microsoft PE and COFF Specification (Rev 11.0) Section 6.6.1: Base Relocation Block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseRelocationBlock {
    /// Page RVA for this block.
    pub page_rva: u32,
    /// Total block size in bytes (including 8-byte header).
    pub size_of_block: u32,
    /// Entries in this block: (RelocationType, offset_within_page).
    pub entries: Vec<(RelocationType, u16)>,
}

/// Parses the base relocation table and computes all fixups for the given target base.
///
/// If `actual_base == headers.optional.image_base`, the table is still fully validated,
/// but returned deltas have `delta == 0`.
pub fn parse_and_compute_relocations(
    headers: &PeHeaders,
    file_bytes: &[u8],
    actual_base: VirtualAddress,
) -> Result<Vec<RelocationDelta>, RelocationError> {
    let reloc_dir = match headers.data_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC) {
        Some(d) if d.is_present() => d,
        _ => return Ok(Vec::new()),
    };

    let dir_rva = reloc_dir.virtual_address;
    let dir_size = reloc_dir.size as usize;

    let dir_offset = headers
        .rva_to_file_offset(dir_rva, file_bytes.len())
        .map_err(|_| RelocationError::DirectoryOutOfBounds {
            rva: dir_rva,
            size: reloc_dir.size,
        })?;

    if dir_offset
        .checked_add(dir_size)
        .is_none_or(|end| end > file_bytes.len())
    {
        return Err(RelocationError::DirectoryOutOfBounds {
            rva: dir_rva,
            size: reloc_dir.size,
        });
    }

    let reloc_bytes = &file_bytes[dir_offset..dir_offset + dir_size];
    let preferred_base = headers.optional.image_base;
    let delta = actual_base.as_u64() as i64 - preferred_base as i64;

    let mut cursor = 0;
    let mut fixups = Vec::new();

    while cursor < reloc_bytes.len() {
        // If remaining bytes are zero padding at the end of the table
        if reloc_bytes[cursor..].iter().all(|&b| b == 0) {
            break;
        }

        // Each block header is 8 bytes: virtual_address (u32), size_of_block (u32)
        if cursor + 8 > reloc_bytes.len() {
            return Err(RelocationError::InvalidBlockHeader {
                offset: dir_offset + cursor,
            });
        }

        let page_rva = u32::from_le_bytes(reloc_bytes[cursor..cursor + 4].try_into().unwrap());
        let size_of_block =
            u32::from_le_bytes(reloc_bytes[cursor + 4..cursor + 8].try_into().unwrap());

        if size_of_block < 8 || (size_of_block % 2) != 0 {
            return Err(RelocationError::BlockSizeTooSmall(size_of_block));
        }

        let block_size = size_of_block as usize;
        let remaining = reloc_bytes.len() - cursor;
        if block_size > remaining {
            return Err(RelocationError::BlockExceedsDirectory {
                block_size: size_of_block,
                remaining,
            });
        }

        let entry_count = (block_size - 8) / 2;
        let entries_start = cursor + 8;

        for i in 0..entry_count {
            let entry_offset = entries_start + i * 2;
            let entry_val = u16::from_le_bytes(
                reloc_bytes[entry_offset..entry_offset + 2]
                    .try_into()
                    .unwrap(),
            );

            let rel_type_nibble = (entry_val >> 12) as u8;
            let offset_in_page = entry_val & 0x0FFF;
            let rel_type = RelocationType::from_nibble(rel_type_nibble);

            match rel_type {
                RelocationType::Absolute => {
                    // Padding entry, no action taken.
                }
                RelocationType::Dir64 => {
                    // Check if 8-byte relocation crosses 4 KiB (4096-byte) page boundary
                    // PE Spec Section 6.6: Each block represents relocations for a 4K page.
                    if offset_in_page > 4096 - 8 {
                        let target_rva = page_rva.saturating_add(offset_in_page as u32);
                        return Err(RelocationError::PageCrossingRelocation {
                            page_rva,
                            offset: offset_in_page,
                            target_rva,
                        });
                    }

                    let target_rva = page_rva.checked_add(offset_in_page as u32).ok_or(
                        RelocationError::RelocationTargetOutOfBounds {
                            target_rva: page_rva,
                        },
                    )?;

                    // Check that the target 8 bytes fall within SizeOfImage
                    if target_rva
                        .checked_add(8)
                        .is_none_or(|end| end > headers.optional.size_of_image)
                    {
                        return Err(RelocationError::RelocationTargetOutOfBounds { target_rva });
                    }

                    // Check that target falls inside a valid mapped section
                    let sec = headers
                        .find_section_by_rva(target_rva)
                        .ok_or(RelocationError::RelocationTargetOutOfBounds { target_rva })?;

                    // Read original 64-bit value from file raw data if present
                    let original_value = if target_rva >= sec.virtual_address
                        && target_rva + 8
                            <= sec.virtual_address.saturating_add(sec.size_of_raw_data)
                    {
                        let file_off = (sec.pointer_to_raw_data as usize)
                            + (target_rva - sec.virtual_address) as usize;
                        if file_off + 8 <= file_bytes.len() {
                            u64::from_le_bytes(
                                file_bytes[file_off..file_off + 8].try_into().unwrap(),
                            )
                        } else {
                            0
                        }
                    } else {
                        0
                    };

                    let relocated_value = original_value.wrapping_add(delta as u64);
                    let target_va = actual_base
                        .checked_add(target_rva as u64)
                        .ok_or(RelocationError::RelocationTargetOutOfBounds { target_rva })?;

                    fixups.push(RelocationDelta {
                        target_rva,
                        target_va,
                        relocation_type: RelocationType::Dir64,
                        delta,
                        original_value,
                        relocated_value,
                    });
                }
                RelocationType::Unsupported(unsupported_type) => {
                    return Err(RelocationError::UnsupportedRelocationType(unsupported_type));
                }
                other => {
                    return Err(RelocationError::UnsupportedRelocationType(match other {
                        RelocationType::High => 1,
                        RelocationType::Low => 2,
                        RelocationType::HighLow => 3,
                        RelocationType::HighAdj => 4,
                        _ => 0xFF,
                    }));
                }
            }
        }

        cursor += block_size;
    }

    Ok(fixups)
}
