//! Shared test helpers for carrick-pe-loader tests.

use carrick_pe_loader::headers::{
    IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_DISCARDABLE, IMAGE_SCN_MEM_READ,
};
use std::fs;
use std::path::{Path, PathBuf};

pub fn get_workspace_root() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    if manifest
        .join("tests/oracle/fixtures/hello_console.exe")
        .exists()
    {
        manifest.to_path_buf()
    } else {
        manifest.parent().unwrap().parent().unwrap().to_path_buf()
    }
}

pub fn get_hello_console_bytes() -> Vec<u8> {
    let path = get_workspace_root().join("tests/oracle/fixtures/hello_console.exe");
    fs::read(&path).expect("failed to read hello_console.exe fixture")
}

/// Constructs a valid PE binary with a synthetic .reloc section added.
pub fn create_pe_with_relocations(
    base_bytes: &[u8],
    page_rva: u32,
    entries: &[(u8, u16)],
) -> Vec<u8> {
    let mut bytes = base_bytes.to_vec();
    let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    let coff_offset = e_lfanew + 4;
    let num_sections =
        u16::from_le_bytes(bytes[coff_offset + 2..coff_offset + 4].try_into().unwrap());
    let size_of_opt = u16::from_le_bytes(
        bytes[coff_offset + 16..coff_offset + 18]
            .try_into()
            .unwrap(),
    ) as usize;
    let opt_offset = coff_offset + 20;

    let sec_table_offset = opt_offset + size_of_opt;
    let new_sec_offset = sec_table_offset + (num_sections as usize) * 40;

    // Increment section count
    bytes[coff_offset + 2..coff_offset + 4].copy_from_slice(&(num_sections + 1).to_le_bytes());

    // New section RVA after existing sections (0x4000)
    let new_sec_rva = 0x4000u32;
    let raw_offset = bytes.len() as u32;

    // Build relocation block
    let block_size = (8 + entries.len() * 2) as u32;
    let padded_block_size = if !block_size.is_multiple_of(4) {
        block_size + 2
    } else {
        block_size
    };

    let mut reloc_data = Vec::new();
    reloc_data.extend_from_slice(&page_rva.to_le_bytes());
    reloc_data.extend_from_slice(&padded_block_size.to_le_bytes());
    for &(rel_type, offset) in entries {
        let entry_val = ((rel_type as u16) << 12) | (offset & 0x0FFF);
        reloc_data.extend_from_slice(&entry_val.to_le_bytes());
    }
    while reloc_data.len() < padded_block_size as usize {
        reloc_data.extend_from_slice(&0u16.to_le_bytes());
    }
    while reloc_data.len() < 512 {
        reloc_data.push(0);
    }

    // Write new section header (40 bytes)
    let mut sec_header = [0u8; 40];
    sec_header[..6].copy_from_slice(b".reloc");
    sec_header[8..12].copy_from_slice(&512u32.to_le_bytes()); // VirtualSize
    sec_header[12..16].copy_from_slice(&new_sec_rva.to_le_bytes()); // VirtualAddress
    sec_header[16..20].copy_from_slice(&512u32.to_le_bytes()); // SizeOfRawData
    sec_header[20..24].copy_from_slice(&raw_offset.to_le_bytes()); // PointerToRawData
    let chars = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE;
    sec_header[36..40].copy_from_slice(&chars.to_le_bytes());

    bytes[new_sec_offset..new_sec_offset + 40].copy_from_slice(&sec_header);

    // Update SizeOfImage: 0x4000 + 0x1000 = 0x5000 (20480)
    let new_image_size = 0x5000u32;
    bytes[opt_offset + 56..opt_offset + 60].copy_from_slice(&new_image_size.to_le_bytes());

    // Update DataDirectory[5] (BaseReloc)
    let dir5_offset = opt_offset + 112 + 5 * 8;
    bytes[dir5_offset..dir5_offset + 4].copy_from_slice(&new_sec_rva.to_le_bytes());
    bytes[dir5_offset + 4..dir5_offset + 8].copy_from_slice(&padded_block_size.to_le_bytes());

    bytes.extend_from_slice(&reloc_data);
    bytes
}
