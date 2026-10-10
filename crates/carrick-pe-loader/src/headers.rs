//! Clean-room PE/COFF header parsing and validation.
//!
//! Conforms strictly to Microsoft PE and COFF Specification (Rev 11.0).

use crate::error::PeError;
use alloc::string::String;
use alloc::vec::Vec;

/// Microsoft PE and COFF Specification (Rev 11.0) Section 3.1: MS-DOS 2.0 Compatible EXE Header.
pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // 'MZ'

/// Microsoft PE and COFF Specification (Rev 11.0) Section 3.3: Signature (Image Only).
pub const IMAGE_NT_SIGNATURE: [u8; 4] = *b"PE\0\0"; // 0x00004550

/// Microsoft PE and COFF Specification (Rev 11.0) Section 3.3.1: Machine Types.
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664; // x64

/// Microsoft PE and COFF Specification (Rev 11.0) Section 3.3.2: Characteristics.
pub const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
pub const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
pub const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
pub const IMAGE_FILE_DLL: u16 = 0x2000;

/// Microsoft PE and COFF Specification (Rev 11.0) Section 3.4.1: Optional Header Standard Fields (Image Only).
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020B; // PE32+

/// Microsoft PE and COFF Specification (Rev 11.0) Section 3.4.2: Windows Subsystem.
pub const IMAGE_SUBSYSTEM_UNKNOWN: u16 = 0;
pub const IMAGE_SUBSYSTEM_NATIVE: u16 = 1;
pub const IMAGE_SUBSYSTEM_WINDOWS_GUI: u16 = 2;
pub const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;

/// Microsoft PE and COFF Specification (Rev 11.0) Section 3.4.2: DLL Characteristics.
pub const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
pub const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;

/// Microsoft PE and COFF Specification (Rev 11.0) Section 3.4.3: Optional Header Data Directories.
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
pub const IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: usize = 7;
pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR: usize = 8;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: usize = 11;
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;
pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

/// Microsoft PE and COFF Specification (Rev 11.0) Section 4.1: Section Flags (Characteristics).
pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
pub const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
pub const IMAGE_SCN_MEM_NOT_CACHED: u32 = 0x0400_0000;
pub const IMAGE_SCN_MEM_NOT_PAGED: u32 = 0x0800_0000;
pub const IMAGE_SCN_MEM_SHARED: u32 = 0x1000_0000;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Parsed DOS header.
/// Microsoft PE and COFF Specification (Rev 11.0) Section 3.1: MS-DOS 2.0 Compatible EXE Header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DosHeader {
    /// Magic number, must be 0x5A4D ('MZ').
    pub e_magic: u16,
    /// Offset to the NT headers. Located at offset 0x3C in the DOS header.
    pub e_lfanew: u32,
}

/// Parsed COFF File Header.
/// Microsoft PE and COFF Specification (Rev 11.0) Section 3.3: COFF File Header (Object and Image).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoffHeader {
    /// Target architecture machine type (IMAGE_FILE_MACHINE_AMD64 = 0x8664).
    pub machine: u16,
    /// Number of sections in the section table.
    pub number_of_sections: u16,
    /// Low 32 bits of POSIX time stamp indicating when file was created.
    pub time_date_stamp: u32,
    /// File offset of the COFF symbol table (0 for images).
    pub pointer_to_symbol_table: u32,
    /// Number of entries in symbol table (0 for images).
    pub number_of_symbols: u32,
    /// Size of the optional header that follows the file header.
    pub size_of_optional_header: u16,
    /// Characteristics flags indicating attributes of the file.
    pub characteristics: u16,
}

/// A data directory entry pointing to an image table.
/// Microsoft PE and COFF Specification (Rev 11.0) Section 3.4.3: Optional Header Data Directories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DataDirectory {
    /// Relative Virtual Address (RVA) of the table.
    pub virtual_address: u32,
    /// Size of the table in bytes.
    pub size: u32,
}

impl DataDirectory {
    /// Returns true if the data directory is present (non-zero RVA and size).
    #[inline]
    pub fn is_present(&self) -> bool {
        self.virtual_address != 0 && self.size != 0
    }
}

/// Parsed Optional Header (PE32+ 64-bit).
/// Microsoft PE and COFF Specification (Rev 11.0) Section 3.4: Optional Header (Image Only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionalHeader64 {
    /// Header format magic (IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x020B).
    pub magic: u16,
    /// Major linker version.
    pub major_linker_version: u8,
    /// Minor linker version.
    pub minor_linker_version: u8,
    /// Size of the code (.text) section.
    pub size_of_code: u32,
    /// Size of the initialized data section.
    pub size_of_initialized_data: u32,
    /// Size of the uninitialized data section (.bss).
    pub size_of_uninitialized_data: u32,
    /// Address of the entry point function RVA.
    pub address_of_entry_point: u32,
    /// Address of the beginning-of-code section RVA.
    pub base_of_code: u32,
    /// Preferred base virtual address of the image when loaded.
    pub image_base: u64,
    /// Alignment of sections in virtual memory (must be power of 2, typically 4096).
    pub section_alignment: u32,
    /// Alignment of sections in the image file (power of 2, typically 512).
    pub file_alignment: u32,
    /// Major operating system version required.
    pub major_operating_system_version: u16,
    /// Minor operating system version required.
    pub minor_operating_system_version: u16,
    /// Major image version.
    pub major_image_version: u16,
    /// Minor image version.
    pub minor_image_version: u16,
    /// Major subsystem version.
    pub major_subsystem_version: u16,
    /// Minor subsystem version.
    pub minor_subsystem_version: u16,
    /// Win32 version value (reserved, must be 0).
    pub win32_version_value: u32,
    /// Size of the image in bytes, including all headers, as loaded into memory.
    pub size_of_image: u32,
    /// Combined size of DOS stub, PE header, and section headers rounded up to FileAlignment.
    pub size_of_headers: u32,
    /// Image file checksum.
    pub check_sum: u32,
    /// Subsystem required to run this image (e.g. IMAGE_SUBSYSTEM_WINDOWS_CUI = 3).
    pub subsystem: u16,
    /// DLL characteristics flags.
    pub dll_characteristics: u16,
    /// Size of stack reserve.
    pub size_of_stack_reserve: u64,
    /// Size of stack commit.
    pub size_of_stack_commit: u64,
    /// Size of local heap space to reserve.
    pub size_of_heap_reserve: u64,
    /// Size of local heap space to commit.
    pub size_of_heap_commit: u64,
    /// Loader flags (reserved, must be 0).
    pub loader_flags: u32,
    /// Number of data-directory entries.
    pub number_of_rva_and_sizes: u32,
    /// Data directories array (up to 16 entries).
    pub data_directories: [DataDirectory; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

/// Parsed Section Header.
/// Microsoft PE and COFF Specification (Rev 11.0) Section 4: Section Table (Section Headers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionHeader {
    /// An 8-byte, null-padded UTF-8 / ASCII string.
    pub name: String,
    /// Total size of the section when loaded into memory.
    pub virtual_size: u32,
    /// Virtual address of the section relative to ImageBase (RVA).
    pub virtual_address: u32,
    /// Size of initialized data on disk.
    pub size_of_raw_data: u32,
    /// File pointer to the first page of the section within the COFF file.
    pub pointer_to_raw_data: u32,
    /// File pointer to relocation entries (0 for executable images).
    pub pointer_to_relocations: u32,
    /// File pointer to line-number entries.
    pub pointer_to_linenumbers: u32,
    /// Number of relocation entries (0 for executable images).
    pub number_of_relocations: u16,
    /// Number of line-number entries.
    pub number_of_linenumbers: u16,
    /// Flags that describe the characteristics of the section.
    pub characteristics: u32,
}

impl SectionHeader {
    /// Returns the virtual span of this section, aligned up to SectionAlignment.
    #[inline]
    pub fn aligned_virtual_span(&self, alignment: u32) -> u32 {
        align_up_u32(self.virtual_size, alignment)
    }

    /// Returns the uninitialized bss span (virtual_size - size_of_raw_data if virtual_size > size_of_raw_data).
    #[inline]
    pub fn zero_fill_len(&self) -> u32 {
        self.virtual_size.saturating_sub(self.size_of_raw_data)
    }
}

/// Complete parsed headers of a PE32+ image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeHeaders {
    /// DOS header.
    pub dos: DosHeader,
    /// COFF file header.
    pub coff: CoffHeader,
    /// Optional header (PE32+).
    pub optional: OptionalHeader64,
    /// Section headers table.
    pub sections: Vec<SectionHeader>,
}

impl PeHeaders {
    /// Parses PE headers from raw file bytes and validates all constraints.
    pub fn parse(bytes: &[u8]) -> Result<Self, PeError> {
        let headers = Self::parse_raw(bytes)?;
        headers.validate(bytes.len())?;
        Ok(headers)
    }

    /// Internal raw parser without cross-section and alignment validation.
    pub fn parse_raw(bytes: &[u8]) -> Result<Self, PeError> {
        if bytes.len() < 0x40 {
            return Err(PeError::FileTooSmall {
                expected: 0x40,
                actual: bytes.len(),
            });
        }

        // 1. DOS Header
        let e_magic = u16::from_le_bytes([bytes[0], bytes[1]]);
        if e_magic != IMAGE_DOS_SIGNATURE {
            return Err(PeError::InvalidDosSignature(e_magic));
        }

        let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap());
        let pe_offset = e_lfanew as usize;
        if pe_offset < 0x40
            || pe_offset
                .checked_add(4 + 20)
                .is_none_or(|end| end > bytes.len())
        {
            return Err(PeError::InvalidPeOffset(pe_offset));
        }

        // 2. PE Signature
        let pe_sig = &bytes[pe_offset..pe_offset + 4];
        if pe_sig != IMAGE_NT_SIGNATURE {
            return Err(PeError::InvalidPeSignature([
                pe_sig[0], pe_sig[1], pe_sig[2], pe_sig[3],
            ]));
        }

        // 3. COFF File Header (20 bytes)
        let coff_off = pe_offset + 4;
        let machine = u16::from_le_bytes(bytes[coff_off..coff_off + 2].try_into().unwrap());
        let number_of_sections =
            u16::from_le_bytes(bytes[coff_off + 2..coff_off + 4].try_into().unwrap());
        let time_date_stamp =
            u32::from_le_bytes(bytes[coff_off + 4..coff_off + 8].try_into().unwrap());
        let pointer_to_symbol_table =
            u32::from_le_bytes(bytes[coff_off + 8..coff_off + 12].try_into().unwrap());
        let number_of_symbols =
            u32::from_le_bytes(bytes[coff_off + 12..coff_off + 16].try_into().unwrap());
        let size_of_optional_header =
            u16::from_le_bytes(bytes[coff_off + 16..coff_off + 18].try_into().unwrap());
        let characteristics =
            u16::from_le_bytes(bytes[coff_off + 18..coff_off + 20].try_into().unwrap());

        if machine != IMAGE_FILE_MACHINE_AMD64 {
            return Err(PeError::UnsupportedMachine(machine));
        }

        if (characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0 {
            return Err(PeError::NotAnExecutableImage(characteristics));
        }

        let coff = CoffHeader {
            machine,
            number_of_sections,
            time_date_stamp,
            pointer_to_symbol_table,
            number_of_symbols,
            size_of_optional_header,
            characteristics,
        };

        // 4. Optional Header (PE32+)
        let opt_off = coff_off + 20;
        let opt_size = size_of_optional_header as usize;
        // Standard PE32+ header without data directories is 112 bytes
        if opt_size < 112
            || opt_off
                .checked_add(opt_size)
                .is_none_or(|end| end > bytes.len())
        {
            return Err(PeError::OptionalHeaderTooSmall {
                expected: 112,
                actual: opt_size,
            });
        }

        let magic = u16::from_le_bytes(bytes[opt_off..opt_off + 2].try_into().unwrap());
        if magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
            return Err(PeError::UnsupportedOptionalHeaderMagic(magic));
        }

        let major_linker_version = bytes[opt_off + 2];
        let minor_linker_version = bytes[opt_off + 3];
        let size_of_code = u32::from_le_bytes(bytes[opt_off + 4..opt_off + 8].try_into().unwrap());
        let size_of_initialized_data =
            u32::from_le_bytes(bytes[opt_off + 8..opt_off + 12].try_into().unwrap());
        let size_of_uninitialized_data =
            u32::from_le_bytes(bytes[opt_off + 12..opt_off + 16].try_into().unwrap());
        let address_of_entry_point =
            u32::from_le_bytes(bytes[opt_off + 16..opt_off + 20].try_into().unwrap());
        let base_of_code =
            u32::from_le_bytes(bytes[opt_off + 20..opt_off + 24].try_into().unwrap());

        // Windows-Specific Fields (PE32+)
        let image_base = u64::from_le_bytes(bytes[opt_off + 24..opt_off + 32].try_into().unwrap());
        let section_alignment =
            u32::from_le_bytes(bytes[opt_off + 32..opt_off + 36].try_into().unwrap());
        let file_alignment =
            u32::from_le_bytes(bytes[opt_off + 36..opt_off + 40].try_into().unwrap());
        let major_operating_system_version =
            u16::from_le_bytes(bytes[opt_off + 40..opt_off + 42].try_into().unwrap());
        let minor_operating_system_version =
            u16::from_le_bytes(bytes[opt_off + 42..opt_off + 44].try_into().unwrap());
        let major_image_version =
            u16::from_le_bytes(bytes[opt_off + 44..opt_off + 46].try_into().unwrap());
        let minor_image_version =
            u16::from_le_bytes(bytes[opt_off + 46..opt_off + 48].try_into().unwrap());
        let major_subsystem_version =
            u16::from_le_bytes(bytes[opt_off + 48..opt_off + 50].try_into().unwrap());
        let minor_subsystem_version =
            u16::from_le_bytes(bytes[opt_off + 50..opt_off + 52].try_into().unwrap());
        let win32_version_value =
            u32::from_le_bytes(bytes[opt_off + 52..opt_off + 56].try_into().unwrap());
        let size_of_image =
            u32::from_le_bytes(bytes[opt_off + 56..opt_off + 60].try_into().unwrap());
        let size_of_headers =
            u32::from_le_bytes(bytes[opt_off + 60..opt_off + 64].try_into().unwrap());
        let check_sum = u32::from_le_bytes(bytes[opt_off + 64..opt_off + 68].try_into().unwrap());
        let subsystem = u16::from_le_bytes(bytes[opt_off + 68..opt_off + 70].try_into().unwrap());
        let dll_characteristics =
            u16::from_le_bytes(bytes[opt_off + 70..opt_off + 72].try_into().unwrap());
        let size_of_stack_reserve =
            u64::from_le_bytes(bytes[opt_off + 72..opt_off + 80].try_into().unwrap());
        let size_of_stack_commit =
            u64::from_le_bytes(bytes[opt_off + 80..opt_off + 88].try_into().unwrap());
        let size_of_heap_reserve =
            u64::from_le_bytes(bytes[opt_off + 88..opt_off + 96].try_into().unwrap());
        let size_of_heap_commit =
            u64::from_le_bytes(bytes[opt_off + 96..opt_off + 104].try_into().unwrap());
        let loader_flags =
            u32::from_le_bytes(bytes[opt_off + 104..opt_off + 108].try_into().unwrap());
        let number_of_rva_and_sizes =
            u32::from_le_bytes(bytes[opt_off + 108..opt_off + 112].try_into().unwrap());

        // Parse Data Directories (up to 16)
        let mut data_directories = [DataDirectory::default(); IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
        let num_dirs = (number_of_rva_and_sizes as usize).min(IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
        let dirs_off = opt_off + 112;

        for (i, dir) in data_directories.iter_mut().enumerate().take(num_dirs) {
            let entry_off = dirs_off + i * 8;
            if entry_off + 8 <= opt_off + opt_size && entry_off + 8 <= bytes.len() {
                let rva = u32::from_le_bytes(bytes[entry_off..entry_off + 4].try_into().unwrap());
                let sz =
                    u32::from_le_bytes(bytes[entry_off + 4..entry_off + 8].try_into().unwrap());
                *dir = DataDirectory {
                    virtual_address: rva,
                    size: sz,
                };
            }
        }

        let optional = OptionalHeader64 {
            magic,
            major_linker_version,
            minor_linker_version,
            size_of_code,
            size_of_initialized_data,
            size_of_uninitialized_data,
            address_of_entry_point,
            base_of_code,
            image_base,
            section_alignment,
            file_alignment,
            major_operating_system_version,
            minor_operating_system_version,
            major_image_version,
            minor_image_version,
            major_subsystem_version,
            minor_subsystem_version,
            win32_version_value,
            size_of_image,
            size_of_headers,
            check_sum,
            subsystem,
            dll_characteristics,
            size_of_stack_reserve,
            size_of_stack_commit,
            size_of_heap_reserve,
            size_of_heap_commit,
            loader_flags,
            number_of_rva_and_sizes,
            data_directories,
        };

        // 5. Section Table (40 bytes each)
        let section_table_offset = opt_off + opt_size;
        let mut sections = Vec::with_capacity(number_of_sections as usize);

        for i in 0..number_of_sections as usize {
            let sec_off = match section_table_offset.checked_add(i * 40) {
                Some(off) => off,
                None => {
                    return Err(PeError::CorruptSectionTable {
                        offset: section_table_offset,
                        count: number_of_sections,
                    })
                }
            };
            if sec_off + 40 > bytes.len() {
                return Err(PeError::CorruptSectionTable {
                    offset: sec_off,
                    count: number_of_sections,
                });
            }

            let name_raw = &bytes[sec_off..sec_off + 8];
            let name_end = name_raw.iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&name_raw[..name_end]).into_owned();

            let virtual_size =
                u32::from_le_bytes(bytes[sec_off + 8..sec_off + 12].try_into().unwrap());
            let virtual_address =
                u32::from_le_bytes(bytes[sec_off + 12..sec_off + 16].try_into().unwrap());
            let size_of_raw_data =
                u32::from_le_bytes(bytes[sec_off + 16..sec_off + 20].try_into().unwrap());
            let pointer_to_raw_data =
                u32::from_le_bytes(bytes[sec_off + 20..sec_off + 24].try_into().unwrap());
            let pointer_to_relocations =
                u32::from_le_bytes(bytes[sec_off + 24..sec_off + 28].try_into().unwrap());
            let pointer_to_linenumbers =
                u32::from_le_bytes(bytes[sec_off + 28..sec_off + 32].try_into().unwrap());
            let number_of_relocations =
                u16::from_le_bytes(bytes[sec_off + 32..sec_off + 34].try_into().unwrap());
            let number_of_linenumbers =
                u16::from_le_bytes(bytes[sec_off + 34..sec_off + 36].try_into().unwrap());
            let characteristics =
                u32::from_le_bytes(bytes[sec_off + 36..sec_off + 40].try_into().unwrap());

            sections.push(SectionHeader {
                name,
                virtual_size,
                virtual_address,
                size_of_raw_data,
                pointer_to_raw_data,
                pointer_to_relocations,
                pointer_to_linenumbers,
                number_of_relocations,
                number_of_linenumbers,
                characteristics,
            });
        }

        Ok(PeHeaders {
            dos: DosHeader { e_magic, e_lfanew },
            coff,
            optional,
            sections,
        })
    }

    /// Performs validation of alignments, bounds, and overlaps.
    pub fn validate(&self, file_len: usize) -> Result<(), PeError> {
        let opt = &self.optional;

        // Subsystem: M1 milestone target is console CUI
        if opt.subsystem != IMAGE_SUBSYSTEM_WINDOWS_CUI {
            return Err(PeError::UnsupportedSubsystem(opt.subsystem));
        }

        // Section alignment must be >= 4096 (standard x86_64 page size)
        if opt.section_alignment < 4096 || !opt.section_alignment.is_power_of_two() {
            return Err(PeError::InvalidAlignment {
                section_alignment: opt.section_alignment,
                file_alignment: opt.file_alignment,
            });
        }

        // File alignment must be power of 2 between 512 and section_alignment
        if opt.file_alignment < 512
            || !opt.file_alignment.is_power_of_two()
            || opt.file_alignment > opt.section_alignment
        {
            return Err(PeError::InvalidAlignment {
                section_alignment: opt.section_alignment,
                file_alignment: opt.file_alignment,
            });
        }

        // SizeOfImage must be multiple of SectionAlignment
        if opt.size_of_image == 0 || !opt.size_of_image.is_multiple_of(opt.section_alignment) {
            return Err(PeError::InvalidImageSize {
                size: opt.size_of_image,
                alignment: opt.section_alignment,
            });
        }

        // SizeOfHeaders must fit within SizeOfImage
        if opt.size_of_headers > opt.size_of_image {
            return Err(PeError::InvalidImageSize {
                size: opt.size_of_image,
                alignment: opt.section_alignment,
            });
        }

        // Entry point RVA check: if non-zero, must be within SizeOfImage
        if opt.address_of_entry_point != 0 && opt.address_of_entry_point >= opt.size_of_image {
            return Err(PeError::OutOfBoundsRva {
                rva: opt.address_of_entry_point,
                context: "AddressOfEntryPoint exceeds SizeOfImage",
            });
        }

        // Validate sections and detect overlaps
        let mut sorted_indices: Vec<usize> = (0..self.sections.len()).collect();
        sorted_indices.sort_by_key(|&idx| self.sections[idx].virtual_address);

        for (order, &idx) in sorted_indices.iter().enumerate() {
            let sec = &self.sections[idx];

            // Section raw data check
            if sec.size_of_raw_data > 0 {
                let raw_end = (sec.pointer_to_raw_data as usize)
                    .checked_add(sec.size_of_raw_data as usize)
                    .ok_or_else(|| PeError::InvalidSectionBounds {
                        name: sec.name.clone(),
                        rva: sec.virtual_address,
                        virtual_size: sec.virtual_size,
                        raw_size: sec.size_of_raw_data,
                    })?;
                if raw_end > file_len {
                    return Err(PeError::InvalidSectionBounds {
                        name: sec.name.clone(),
                        rva: sec.virtual_address,
                        virtual_size: sec.virtual_size,
                        raw_size: sec.size_of_raw_data,
                    });
                }
            }

            // Virtual span check: section cannot overlap headers
            if sec.virtual_address < opt.size_of_headers {
                return Err(PeError::HeaderSectionOverlap {
                    section: sec.name.clone(),
                    sec_rva: sec.virtual_address,
                    size_of_headers: opt.size_of_headers,
                });
            }

            // Virtual span must not overflow or exceed SizeOfImage
            let span = sec.aligned_virtual_span(opt.section_alignment);
            let sec_end = sec.virtual_address.checked_add(span).ok_or_else(|| {
                PeError::InvalidSectionBounds {
                    name: sec.name.clone(),
                    rva: sec.virtual_address,
                    virtual_size: sec.virtual_size,
                    raw_size: sec.size_of_raw_data,
                }
            })?;

            if sec_end > opt.size_of_image {
                return Err(PeError::InvalidSectionBounds {
                    name: sec.name.clone(),
                    rva: sec.virtual_address,
                    virtual_size: sec.virtual_size,
                    raw_size: sec.size_of_raw_data,
                });
            }

            // Check overlap with next sorted section
            if order + 1 < sorted_indices.len() {
                let next_sec = &self.sections[sorted_indices[order + 1]];
                if sec_end > next_sec.virtual_address {
                    let next_span = next_sec.aligned_virtual_span(opt.section_alignment);
                    return Err(PeError::OverlappingSections {
                        first: sec.name.clone(),
                        second: next_sec.name.clone(),
                        first_span: (sec.virtual_address, sec_end),
                        second_span: (
                            next_sec.virtual_address,
                            next_sec.virtual_address.saturating_add(next_span),
                        ),
                    });
                }
            }
        }

        // Validate data directories: if present, must fall within SizeOfImage
        for (i, dir) in opt.data_directories.iter().enumerate() {
            if dir.is_present() {
                let dir_end = dir
                    .virtual_address
                    .checked_add(dir.size)
                    .ok_or(PeError::MalformedDataDirectory { entry: i })?;
                if dir_end > opt.size_of_image {
                    return Err(PeError::MalformedDataDirectory { entry: i });
                }
            }
        }

        Ok(())
    }

    /// Resolves an RVA to a file offset using the section table.
    pub fn rva_to_file_offset(&self, rva: u32, file_len: usize) -> Result<usize, PeError> {
        // If RVA is within headers
        if rva < self.optional.size_of_headers {
            let offset = rva as usize;
            if offset <= file_len {
                return Ok(offset);
            }
            return Err(PeError::UnmappedRva(rva));
        }

        for sec in &self.sections {
            // Raw data covers [virtual_address .. virtual_address + size_of_raw_data)
            if rva >= sec.virtual_address
                && rva < sec.virtual_address.saturating_add(sec.size_of_raw_data)
            {
                let delta = (rva - sec.virtual_address) as usize;
                let file_offset = (sec.pointer_to_raw_data as usize)
                    .checked_add(delta)
                    .ok_or(PeError::UnmappedRva(rva))?;
                if file_offset <= file_len {
                    return Ok(file_offset);
                }
            }
        }
        Err(PeError::UnmappedRva(rva))
    }

    /// Reads a null-terminated ASCII string starting at the given RVA.
    pub fn read_null_terminated_ascii(&self, bytes: &[u8], rva: u32) -> Result<String, PeError> {
        let offset = self.rva_to_file_offset(rva, bytes.len())?;
        let mut end = offset;
        while end < bytes.len() && bytes[end] != 0 {
            end += 1;
        }
        if end >= bytes.len() {
            return Err(PeError::InvalidString { offset });
        }
        Ok(String::from_utf8_lossy(&bytes[offset..end]).into_owned())
    }

    /// Returns a reference to the specified data directory.
    #[inline]
    pub fn data_directory(&self, entry: usize) -> Option<&DataDirectory> {
        self.optional.data_directories.get(entry)
    }

    /// Finds the section containing the given RVA, if any.
    pub fn find_section_by_rva(&self, rva: u32) -> Option<&SectionHeader> {
        self.sections.iter().find(|sec| {
            let span = sec.aligned_virtual_span(self.optional.section_alignment);
            rva >= sec.virtual_address && rva < sec.virtual_address.saturating_add(span)
        })
    }
}

/// Helper function to align up a u32 value to an alignment (power of 2).
#[inline]
pub fn align_up_u32(val: u32, alignment: u32) -> u32 {
    if alignment == 0 {
        return val;
    }
    let mask = alignment - 1;
    (val.saturating_add(mask)) & !mask
}

/// Helper function to align up a u64 value to an alignment (power of 2).
#[inline]
pub fn align_up_u64(val: u64, alignment: u64) -> u64 {
    if alignment == 0 {
        return val;
    }
    let mask = alignment - 1;
    (val.saturating_add(mask)) & !mask
}
