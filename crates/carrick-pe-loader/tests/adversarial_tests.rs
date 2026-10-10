//! Adversarial and malformed PE input tests.
//!
//! Conforms to Microsoft PE and COFF Specification (Rev 11.0).
//!
//! Validates that all malformed and hostile inputs are rejected with
//! typed errors and NEVER panic:
//! - Truncated headers
//! - Overlapping sections
//! - Out-of-bounds RVAs
//! - Relocation blocks that cross pages
//! - Import name RVAs outside sections

mod common;

use carrick_pe_loader::error::{ImportError, PeError, RelocationError};
use carrick_pe_loader::mapper::PeLoader;
use carrick_pe_loader::plan::VirtualAddress;
use common::{create_pe_with_relocations, get_hello_console_bytes};

// ---------------------------------------------------------------------------
// 1. Truncated & Invalid Headers
// ---------------------------------------------------------------------------

#[test]
fn test_truncated_file_too_small() {
    let loader = PeLoader::default();

    // Empty file
    let err = loader.load(&[]).unwrap_err();
    assert!(matches!(err, PeError::FileTooSmall { .. }));

    // Less than DOS header (0x40 bytes)
    let err = loader.load(&[0u8; 0x3F]).unwrap_err();
    assert!(matches!(err, PeError::FileTooSmall { .. }));
}

#[test]
fn test_invalid_dos_signature() {
    let loader = PeLoader::default();
    let mut data = vec![0u8; 0x100];
    data[0] = b'Z';
    data[1] = b'M'; // Reversed or wrong signature
    let err = loader.load(&data).unwrap_err();
    assert!(matches!(err, PeError::InvalidDosSignature(..)));
}

#[test]
fn test_invalid_pe_offset() {
    let loader = PeLoader::default();
    let mut data = vec![0u8; 0x100];
    data[0] = b'M';
    data[1] = b'Z';

    // e_lfanew < 0x40
    data[0x3C..0x40].copy_from_slice(&0x20u32.to_le_bytes());
    let err = loader.load(&data).unwrap_err();
    assert!(matches!(err, PeError::InvalidPeOffset(0x20)));

    // e_lfanew out of bounds
    data[0x3C..0x40].copy_from_slice(&0x5000u32.to_le_bytes());
    let err = loader.load(&data).unwrap_err();
    assert!(matches!(err, PeError::InvalidPeOffset(0x5000)));
}

#[test]
fn test_invalid_pe_signature() {
    let loader = PeLoader::default();
    let mut data = vec![0u8; 0x100];
    data[0] = b'M';
    data[1] = b'Z';
    data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    data[0x80..0x84].copy_from_slice(b"NE\0\0"); // Not PE
    let err = loader.load(&data).unwrap_err();
    assert!(matches!(err, PeError::InvalidPeSignature(..)));
}

#[test]
fn test_unsupported_machine() {
    let mut bytes = get_hello_console_bytes();
    let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    // Machine field is at e_lfanew + 4
    let machine_offset = e_lfanew + 4;
    // Set to i386 (0x014c)
    bytes[machine_offset..machine_offset + 2].copy_from_slice(&0x014cu16.to_le_bytes());

    let loader = PeLoader::default();
    let err = loader.load(&bytes).unwrap_err();
    assert_eq!(err, PeError::UnsupportedMachine(0x014c));
}

#[test]
fn test_unsupported_optional_header_magic() {
    let mut bytes = get_hello_console_bytes();
    let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    // Optional Header starts at e_lfanew + 4 + 20
    let opt_offset = e_lfanew + 24;
    // Set to PE32 (0x010B) instead of PE32+ (0x020B)
    bytes[opt_offset..opt_offset + 2].copy_from_slice(&0x010Bu16.to_le_bytes());

    let loader = PeLoader::default();
    let err = loader.load(&bytes).unwrap_err();
    assert_eq!(err, PeError::UnsupportedOptionalHeaderMagic(0x010B));
}

#[test]
fn test_unsupported_subsystem() {
    let mut bytes = get_hello_console_bytes();
    let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    let opt_offset = e_lfanew + 24;
    // Subsystem field is at opt_offset + 68
    let subsys_offset = opt_offset + 68;
    // Change subsystem to GUI (2)
    bytes[subsys_offset..subsys_offset + 2].copy_from_slice(&2u16.to_le_bytes());

    let loader = PeLoader::default();
    let err = loader.load(&bytes).unwrap_err();
    assert_eq!(err, PeError::UnsupportedSubsystem(2));
}

#[test]
fn test_corrupt_section_table_truncated() {
    let mut bytes = get_hello_console_bytes();
    let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    // NumberOfSections is at e_lfanew + 4 + 2
    let num_sec_offset = e_lfanew + 6;
    // Declare 100 sections, which exceeds file size
    bytes[num_sec_offset..num_sec_offset + 2].copy_from_slice(&100u16.to_le_bytes());

    let loader = PeLoader::default();
    let err = loader.load(&bytes).unwrap_err();
    assert!(matches!(err, PeError::CorruptSectionTable { .. }));
}

// ---------------------------------------------------------------------------
// 2. Overlapping Sections & Header Overlap
// ---------------------------------------------------------------------------

#[test]
fn test_header_section_overlap() {
    let mut bytes = get_hello_console_bytes();
    let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    let opt_offset = e_lfanew + 24;
    let size_of_opt =
        u16::from_le_bytes(bytes[e_lfanew + 20..e_lfanew + 22].try_into().unwrap()) as usize;
    let sec_table_offset = opt_offset + size_of_opt;

    // First section virtual address is at sec_table_offset + 12
    // Force first section RVA to 0x100, which is inside SizeOfHeaders (typically 0x400 or 0x1000)
    bytes[sec_table_offset + 12..sec_table_offset + 16].copy_from_slice(&0x100u32.to_le_bytes());

    let loader = PeLoader::default();
    let err = loader.load(&bytes).unwrap_err();
    assert!(matches!(err, PeError::HeaderSectionOverlap { .. }));
}

#[test]
fn test_overlapping_sections() {
    let mut bytes = get_hello_console_bytes();
    let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    let opt_offset = e_lfanew + 24;
    let size_of_opt =
        u16::from_le_bytes(bytes[e_lfanew + 20..e_lfanew + 22].try_into().unwrap()) as usize;
    let sec_table_offset = opt_offset + size_of_opt;

    // Section 0 VirtualAddress is at sec_table_offset + 12
    // Section 1 VirtualAddress is at sec_table_offset + 40 + 12
    let sec0_rva = u32::from_le_bytes(
        bytes[sec_table_offset + 12..sec_table_offset + 16]
            .try_into()
            .unwrap(),
    );
    // Move section 1 VirtualAddress to equal section 0 VirtualAddress (overlap)
    bytes[sec_table_offset + 40 + 12..sec_table_offset + 40 + 16]
        .copy_from_slice(&sec0_rva.to_le_bytes());

    let loader = PeLoader::default();
    let err = loader.load(&bytes).unwrap_err();
    assert!(matches!(err, PeError::OverlappingSections { .. }));
}

// ---------------------------------------------------------------------------
// 3. Out-of-Bounds RVAs
// ---------------------------------------------------------------------------

#[test]
fn test_out_of_bounds_entry_point() {
    let mut bytes = get_hello_console_bytes();
    let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    let opt_offset = e_lfanew + 24;
    // AddressOfEntryPoint is at opt_offset + 16
    let entry_point_off = opt_offset + 16;
    // Set entry point to 0xF000_0000, exceeding SizeOfImage
    bytes[entry_point_off..entry_point_off + 4].copy_from_slice(&0xF000_0000u32.to_le_bytes());

    let loader = PeLoader::default();
    let err = loader.load(&bytes).unwrap_err();
    assert!(matches!(err, PeError::OutOfBoundsRva { .. }));
}

#[test]
fn test_section_exceeds_image_size() {
    let mut bytes = get_hello_console_bytes();
    let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    let opt_offset = e_lfanew + 24;
    let size_of_opt =
        u16::from_le_bytes(bytes[e_lfanew + 20..e_lfanew + 22].try_into().unwrap()) as usize;
    let sec_table_offset = opt_offset + size_of_opt;

    // Last section VirtualSize at sec_table_offset + 8
    // Inflate VirtualSize to exceed SizeOfImage
    bytes[sec_table_offset + 8..sec_table_offset + 12]
        .copy_from_slice(&0x1000_0000u32.to_le_bytes());

    let loader = PeLoader::default();
    let err = loader.load(&bytes).unwrap_err();
    assert!(matches!(err, PeError::InvalidSectionBounds { .. }));
}

#[test]
fn test_data_directory_out_of_bounds() {
    let mut bytes = get_hello_console_bytes();
    let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    let opt_offset = e_lfanew + 24;
    let dirs_off = opt_offset + 112;

    // Export directory is entry 0: RVA at dirs_off, Size at dirs_off + 4
    bytes[dirs_off..dirs_off + 4].copy_from_slice(&0x8000_0000u32.to_le_bytes());
    bytes[dirs_off + 4..dirs_off + 8].copy_from_slice(&0x1000u32.to_le_bytes());

    let loader = PeLoader::default();
    let err = loader.load(&bytes).unwrap_err();
    assert!(matches!(err, PeError::MalformedDataDirectory { entry: 0 }));
}

// ---------------------------------------------------------------------------
// 4. Relocation Blocks That Cross Pages & Malformed Relocations
// ---------------------------------------------------------------------------

#[test]
fn test_relocation_crossing_page_boundary() {
    let base_bytes = get_hello_console_bytes();
    // Offset 4092 with DIR64 (8 bytes) crosses the 4096-byte page boundary (4092 + 8 = 4100 > 4096)
    let bad_offset = 4092u16;
    let bytes = create_pe_with_relocations(&base_bytes, 0x2000, &[(10, bad_offset)]);

    let loader = PeLoader::default().with_base(VirtualAddress::new(0x200000000));
    let err = loader.load(&bytes).unwrap_err();

    match err {
        PeError::Relocation(RelocationError::PageCrossingRelocation { offset, .. }) => {
            assert_eq!(offset, bad_offset);
        }
        other => panic!("Expected PageCrossingRelocation, got: {other:?}"),
    }
}

#[test]
fn test_relocation_block_size_too_small() {
    let base_bytes = get_hello_console_bytes();
    let mut bytes = create_pe_with_relocations(&base_bytes, 0x2000, &[(10, 0x10)]);

    let headers = carrick_pe_loader::headers::PeHeaders::parse(&bytes).unwrap();
    let reloc_dir = headers.data_directory(5).unwrap();
    let dir_offset = headers
        .rva_to_file_offset(reloc_dir.virtual_address, bytes.len())
        .unwrap();

    // Block size is at dir_offset + 4. Set to 6 bytes (< 8 minimum).
    bytes[dir_offset + 4..dir_offset + 8].copy_from_slice(&6u32.to_le_bytes());

    let loader = PeLoader::default().with_base(VirtualAddress::new(0x200000000));
    let err = loader.load(&bytes).unwrap_err();
    assert!(matches!(
        err,
        PeError::Relocation(RelocationError::BlockSizeTooSmall(6))
    ));
}

#[test]
fn test_unsupported_relocation_type() {
    let base_bytes = get_hello_console_bytes();
    // Type 5 is MIPS_JMPADDR / ARM_MOV32 - unsupported on AMD64
    let bytes = create_pe_with_relocations(&base_bytes, 0x2000, &[(5, 0x10)]);

    let loader = PeLoader::default().with_base(VirtualAddress::new(0x200000000));
    let err = loader.load(&bytes).unwrap_err();
    assert!(matches!(
        err,
        PeError::Relocation(RelocationError::UnsupportedRelocationType(5))
    ));
}

// ---------------------------------------------------------------------------
// 5. Import Name RVAs Outside Sections
// ---------------------------------------------------------------------------

#[test]
fn test_import_dll_name_rva_outside_sections() {
    let mut bytes = get_hello_console_bytes();
    let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    let opt_offset = e_lfanew + 24;
    let dirs_off = opt_offset + 112;

    // Import directory is entry 1
    let import_dir_rva = u32::from_le_bytes(bytes[dirs_off + 8..dirs_off + 12].try_into().unwrap());
    let headers = carrick_pe_loader::headers::PeHeaders::parse(&bytes).unwrap();
    let desc_offset = headers
        .rva_to_file_offset(import_dir_rva, bytes.len())
        .unwrap();

    // In IMAGE_IMPORT_DESCRIPTOR, Name RVA is at offset 12
    let bad_name_rva = 0x00FF_0000u32; // Unmapped RVA outside any section
    bytes[desc_offset + 12..desc_offset + 16].copy_from_slice(&bad_name_rva.to_le_bytes());

    let loader = PeLoader::default();
    let err = loader.load(&bytes).unwrap_err();
    assert_eq!(
        err,
        PeError::Import(ImportError::UnmappedDllNameRva(bad_name_rva))
    );
}

#[test]
fn test_import_by_name_rva_outside_sections() {
    let mut bytes = get_hello_console_bytes();
    let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    let opt_offset = e_lfanew + 24;
    let dirs_off = opt_offset + 112;

    let import_dir_rva = u32::from_le_bytes(bytes[dirs_off + 8..dirs_off + 12].try_into().unwrap());
    let headers = carrick_pe_loader::headers::PeHeaders::parse(&bytes).unwrap();
    let desc_offset = headers
        .rva_to_file_offset(import_dir_rva, bytes.len())
        .unwrap();

    // OriginalFirstThunk (ILT) is at desc_offset + 0
    let ilt_rva = u32::from_le_bytes(bytes[desc_offset..desc_offset + 4].try_into().unwrap());
    let ilt_offset = headers.rva_to_file_offset(ilt_rva, bytes.len()).unwrap();

    // Point the first ILT entry to an unmapped RVA outside sections
    let bad_ibn_rva = 0x00EE_0000u64;
    bytes[ilt_offset..ilt_offset + 8].copy_from_slice(&bad_ibn_rva.to_le_bytes());

    let loader = PeLoader::default();
    let err = loader.load(&bytes).unwrap_err();
    assert_eq!(
        err,
        PeError::Import(ImportError::UnmappedImportByNameRva(bad_ibn_rva as u32))
    );
}
