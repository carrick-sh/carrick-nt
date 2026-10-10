//! Typed error definitions for PE parsing, relocation, import resolution, and memory mapping.
//!
//! Conforms to Microsoft PE and COFF Specification (Rev 11.0).

use alloc::string::String;
use core::fmt;

/// Top-level error for PE parsing, validation, and mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeError {
    /// File is too small to contain the required structure.
    FileTooSmall { expected: usize, actual: usize },
    /// Invalid DOS magic number (expected 0x5A4D 'MZ').
    /// PE Specification Section 3.1: MS-DOS 2.0 Compatible EXE Header.
    InvalidDosSignature(u16),
    /// e_lfanew points outside the file or is before the DOS header end (0x40).
    /// PE Specification Section 3.1: e_lfanew is offset 0x3C to NT headers.
    InvalidPeOffset(usize),
    /// Invalid PE signature (expected b"PE\0\0" = 0x00004550).
    /// PE Specification Section 3.3: Signature (Image Only).
    InvalidPeSignature([u8; 4]),
    /// Unsupported machine architecture (expected AMD64 0x8664).
    /// PE Specification Section 3.3.1: Machine Types.
    UnsupportedMachine(u16),
    /// File is not marked as an executable image.
    /// PE Specification Section 3.3.2: Characteristics (IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002).
    NotAnExecutableImage(u16),
    /// Optional header magic mismatch (expected PE32+ 0x020B).
    /// PE Specification Section 3.4.1: Optional Header Standard Fields.
    UnsupportedOptionalHeaderMagic(u16),
    /// Optional header is too small to contain declared fields.
    OptionalHeaderTooSmall { expected: usize, actual: usize },
    /// Subsystem is not supported (milestone M1 supports WINDOWS_CUI = 3).
    /// PE Specification Section 3.4.2: Windows Subsystem.
    UnsupportedSubsystem(u16),
    /// Invalid alignment parameters. Section alignment must be >= 4096 and >= file alignment.
    /// PE Specification Section 3.4.2: SectionAlignment and FileAlignment.
    InvalidAlignment {
        section_alignment: u32,
        file_alignment: u32,
    },
    /// SizeOfImage is not a multiple of SectionAlignment or is too small.
    /// PE Specification Section 3.4.2: SizeOfImage.
    InvalidImageSize { size: u32, alignment: u32 },
    /// Section table contains invalid or truncated headers.
    /// PE Specification Section 4: Section Table.
    CorruptSectionTable { offset: usize, count: u16 },
    /// Section headers overlap with image headers.
    HeaderSectionOverlap {
        section: String,
        sec_rva: u32,
        size_of_headers: u32,
    },
    /// Two sections overlap in virtual address space.
    /// PE Specification Section 4: Section Table.
    OverlappingSections {
        first: String,
        second: String,
        first_span: (u32, u32),
        second_span: (u32, u32),
    },
    /// Section has invalid bounds (RVA or size exceeds image limits or integer overflow).
    InvalidSectionBounds {
        name: String,
        rva: u32,
        virtual_size: u32,
        raw_size: u32,
    },
    /// Out-of-bounds Relative Virtual Address (RVA).
    OutOfBoundsRva { rva: u32, context: &'static str },
    /// RVA cannot be mapped to any section file offset.
    UnmappedRva(u32),
    /// String is not null-terminated or contains non-ASCII characters within bounds.
    InvalidString { offset: usize },
    /// Data directory entry is out of bounds or malformed.
    /// PE Specification Section 3.4.3: Data Directories.
    MalformedDataDirectory { entry: usize },
    /// Relocation processing error.
    /// PE Specification Section 6.6: The .reloc Section.
    Relocation(RelocationError),
    /// Import directory or thunk resolution error.
    /// PE Specification Section 6.4: The .idata Section.
    Import(ImportError),
    /// Thread Local Storage directory error.
    /// PE Specification Section 6.7: The .tls Section.
    Tls(TlsError),
    /// Mapping plan generation or application error.
    Mapping(MappingError),
}

/// Errors occurring during base relocation processing.
/// Conforms to PE Specification Section 6.6: The .reloc Section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelocationError {
    /// Relocation directory bounds exceed file or image.
    DirectoryOutOfBounds { rva: u32, size: u32 },
    /// Invalid relocation block header.
    InvalidBlockHeader { offset: usize },
    /// Block size is less than header size (8 bytes) or not a multiple of 2.
    /// PE Specification Section 6.6: Block Size must include the 8-byte header.
    BlockSizeTooSmall(u32),
    /// Block size claims more bytes than remain in the relocation table.
    BlockExceedsDirectory { block_size: u32, remaining: usize },
    /// Relocation fixup crosses a 4 KiB page boundary.
    /// PE Specification Section 6.6: Each block represents relocations for a 4K page.
    PageCrossingRelocation {
        page_rva: u32,
        offset: u16,
        target_rva: u32,
    },
    /// Unsupported relocation type encountered.
    /// PE Specification Section 6.6.2: Base Relocation Types.
    UnsupportedRelocationType(u8),
    /// Relocation target RVA falls outside of valid sections or image bounds.
    RelocationTargetOutOfBounds { target_rva: u32 },
    /// Memory buffer too small to apply relocation.
    BufferTooSmall { required: usize, actual: usize },
}

/// Errors occurring during import directory resolution.
/// Conforms to PE Specification Section 6.4: The .idata Section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportError {
    /// Import directory bounds exceed file or image.
    DirectoryOutOfBounds { rva: u32, size: u32 },
    /// Import descriptor entry truncated or unmapped.
    DescriptorOutOfBounds { offset: usize },
    /// DLL name RVA does not point within any valid mapped section.
    UnmappedDllNameRva(u32),
    /// DLL name string is not null-terminated within section bounds.
    InvalidDllName(usize),
    /// Import Lookup Table or Import Address Table RVA is unmapped.
    UnmappedThunkRva(u32),
    /// Hint/Name table entry RVA does not point within any mapped section.
    /// PE Specification Section 6.4: Hint/Name Table (IMAGE_IMPORT_BY_NAME).
    UnmappedImportByNameRva(u32),
    /// Symbol could not be resolved by the export provider.
    SymbolNotFound { dll: String, symbol: String },
    /// Ordinal could not be resolved by the export provider.
    OrdinalNotFound { dll: String, ordinal: u16 },
}

/// Errors occurring during export directory parsing.
/// Conforms to PE Specification Section 6.3: The .edata Section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportError {
    /// Export directory bounds exceed file or image.
    DirectoryOutOfBounds { rva: u32, size: u32 },
    /// Export directory header is truncated or out of bounds.
    HeaderOutOfBounds { offset: usize },
    /// An RVA within the export directory does not point within any mapped section.
    UnmappedRva { rva: u32, context: &'static str },
    /// ASCII name or forwarder string is not null-terminated within section bounds.
    InvalidString { offset: usize },
}

/// Errors occurring during TLS directory parsing.
/// Conforms to PE Specification Section 6.7: The .tls Section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsError {
    /// TLS directory bounds exceed file or image.
    DirectoryOutOfBounds { rva: u32, size: u32 },
    /// TLS directory header is smaller than IMAGE_TLS_DIRECTORY64 (40 bytes).
    DirectoryTooSmall { expected: usize, actual: usize },
    /// Raw data address range is inverted (start > end).
    InvalidRawDataRange { start: u64, end: u64 },
    /// Callback array address is unmapped.
    UnmappedCallbackAddress(u64),
}

/// Errors occurring during mapping plan generation and buffer application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappingError {
    /// Buffer provided for mapping is smaller than required SizeOfImage.
    BufferTooSmall { required: usize, actual: usize },
    /// Raw data offset and size exceed file bounds.
    RawDataExceedsFile {
        name: String,
        offset: u32,
        size: u32,
        file_len: usize,
    },
    /// Region bounds exceed total image virtual size.
    RegionOutOfBounds { name: String, va: u64, size: u64 },
}

impl From<RelocationError> for PeError {
    fn from(e: RelocationError) -> Self {
        PeError::Relocation(e)
    }
}

impl From<ImportError> for PeError {
    fn from(e: ImportError) -> Self {
        PeError::Import(e)
    }
}

impl From<TlsError> for PeError {
    fn from(e: TlsError) -> Self {
        PeError::Tls(e)
    }
}

impl From<MappingError> for PeError {
    fn from(e: MappingError) -> Self {
        PeError::Mapping(e)
    }
}

impl fmt::Display for PeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeError::FileTooSmall { expected, actual } => {
                write!(
                    f,
                    "file too small: expected >= {expected} bytes, got {actual}"
                )
            }
            PeError::InvalidDosSignature(magic) => {
                write!(
                    f,
                    "invalid DOS signature: expected 0x5a4d ('MZ'), got 0x{magic:04x}"
                )
            }
            PeError::InvalidPeOffset(off) => {
                write!(f, "invalid PE offset (e_lfanew = 0x{off:x})")
            }
            PeError::InvalidPeSignature(sig) => {
                write!(f, "invalid PE signature: expected 'PE\\0\\0', got {sig:?}")
            }
            PeError::UnsupportedMachine(m) => {
                write!(
                    f,
                    "unsupported machine architecture: expected AMD64 (0x8664), got 0x{m:04x}"
                )
            }
            PeError::NotAnExecutableImage(chars) => {
                write!(
                    f,
                    "image is not marked as executable (characteristics: 0x{chars:04x})"
                )
            }
            PeError::UnsupportedOptionalHeaderMagic(m) => {
                write!(
                    f,
                    "unsupported optional header magic: expected PE32+ (0x020b), got 0x{m:04x}"
                )
            }
            PeError::OptionalHeaderTooSmall { expected, actual } => {
                write!(
                    f,
                    "optional header too small: expected >= {expected}, got {actual}"
                )
            }
            PeError::UnsupportedSubsystem(s) => {
                write!(
                    f,
                    "unsupported subsystem: expected Windows CUI (3), got {s}"
                )
            }
            PeError::InvalidAlignment {
                section_alignment,
                file_alignment,
            } => {
                write!(f, "invalid alignment: section alignment {section_alignment:#x}, file alignment {file_alignment:#x}")
            }
            PeError::InvalidImageSize { size, alignment } => {
                write!(f, "invalid image size {size:#x}: not a multiple of section alignment {alignment:#x}")
            }
            PeError::CorruptSectionTable { offset, count } => {
                write!(
                    f,
                    "corrupt section table at offset {offset:#x} with {count} sections"
                )
            }
            PeError::HeaderSectionOverlap {
                section,
                sec_rva,
                size_of_headers,
            } => {
                write!(f, "section '{section}' at RVA {sec_rva:#x} overlaps headers (size: {size_of_headers:#x})")
            }
            PeError::OverlappingSections {
                first,
                second,
                first_span,
                second_span,
            } => {
                write!(
                    f,
                    "sections overlap: '{first}' [{:#x}..{:#x}) and '{second}' [{:#x}..{:#x})",
                    first_span.0, first_span.1, second_span.0, second_span.1
                )
            }
            PeError::InvalidSectionBounds {
                name,
                rva,
                virtual_size,
                raw_size,
            } => {
                write!(f, "invalid section bounds for '{name}': RVA {rva:#x}, vsize {virtual_size:#x}, raw {raw_size:#x}")
            }
            PeError::OutOfBoundsRva { rva, context } => {
                write!(f, "out of bounds RVA {rva:#x} in context: {context}")
            }
            PeError::UnmappedRva(rva) => {
                write!(f, "RVA {rva:#x} could not be resolved to any section")
            }
            PeError::InvalidString { offset } => {
                write!(
                    f,
                    "string at offset {offset:#x} is invalid or not null-terminated"
                )
            }
            PeError::MalformedDataDirectory { entry } => {
                write!(f, "malformed data directory at index {entry}")
            }
            PeError::Relocation(e) => write!(f, "relocation error: {e}"),
            PeError::Import(e) => write!(f, "import error: {e}"),
            PeError::Tls(e) => write!(f, "tls error: {e}"),
            PeError::Mapping(e) => write!(f, "mapping error: {e}"),
        }
    }
}

impl fmt::Display for RelocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelocationError::DirectoryOutOfBounds { rva, size } => {
                write!(
                    f,
                    "relocation directory bounds out of image: RVA {rva:#x}, size {size:#x}"
                )
            }
            RelocationError::InvalidBlockHeader { offset } => {
                write!(f, "invalid relocation block header at offset {offset:#x}")
            }
            RelocationError::BlockSizeTooSmall(size) => {
                write!(
                    f,
                    "relocation block size {size:#x} is smaller than minimum (8 bytes)"
                )
            }
            RelocationError::BlockExceedsDirectory {
                block_size,
                remaining,
            } => {
                write!(f, "relocation block size {block_size:#x} exceeds remaining directory {remaining:#x}")
            }
            RelocationError::PageCrossingRelocation {
                page_rva,
                offset,
                target_rva,
            } => {
                write!(f, "relocation crosses 4K page boundary: page RVA {page_rva:#x} + offset {offset:#x} -> target {target_rva:#x}")
            }
            RelocationError::UnsupportedRelocationType(t) => {
                write!(f, "unsupported base relocation type {t}")
            }
            RelocationError::RelocationTargetOutOfBounds { target_rva } => {
                write!(f, "relocation target RVA {target_rva:#x} is out of bounds")
            }
            RelocationError::BufferTooSmall { required, actual } => {
                write!(
                    f,
                    "relocation target buffer too small: required {required}, actual {actual}"
                )
            }
        }
    }
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImportError::DirectoryOutOfBounds { rva, size } => {
                write!(
                    f,
                    "import directory bounds out of image: RVA {rva:#x}, size {size:#x}"
                )
            }
            ImportError::DescriptorOutOfBounds { offset } => {
                write!(
                    f,
                    "import descriptor at offset {offset:#x} exceeds table bounds"
                )
            }
            ImportError::UnmappedDllNameRva(rva) => {
                write!(f, "import DLL name RVA {rva:#x} is not within any section")
            }
            ImportError::InvalidDllName(off) => {
                write!(f, "import DLL name string at offset {off:#x} is invalid")
            }
            ImportError::UnmappedThunkRva(rva) => {
                write!(f, "import thunk table RVA {rva:#x} is unmapped")
            }
            ImportError::UnmappedImportByNameRva(rva) => {
                write!(f, "import name RVA {rva:#x} is not within any section")
            }
            ImportError::SymbolNotFound { dll, symbol } => {
                write!(f, "symbol '{symbol}' from '{dll}' could not be resolved")
            }
            ImportError::OrdinalNotFound { dll, ordinal } => {
                write!(f, "ordinal #{ordinal} from '{dll}' could not be resolved")
            }
        }
    }
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsError::DirectoryOutOfBounds { rva, size } => {
                write!(
                    f,
                    "TLS directory out of bounds: RVA {rva:#x}, size {size:#x}"
                )
            }
            TlsError::DirectoryTooSmall { expected, actual } => {
                write!(
                    f,
                    "TLS directory too small: expected {expected}, actual {actual}"
                )
            }
            TlsError::InvalidRawDataRange { start, end } => {
                write!(
                    f,
                    "TLS raw data range invalid: start {start:#x} > end {end:#x}"
                )
            }
            TlsError::UnmappedCallbackAddress(va) => {
                write!(f, "TLS callback array at {va:#x} is unmapped")
            }
        }
    }
}

impl fmt::Display for ExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExportError::DirectoryOutOfBounds { rva, size } => {
                write!(
                    f,
                    "export directory out of bounds: RVA {rva:#x}, size {size:#x}"
                )
            }
            ExportError::HeaderOutOfBounds { offset } => {
                write!(
                    f,
                    "export directory header out of bounds at offset {offset:#x}"
                )
            }
            ExportError::UnmappedRva { rva, context } => {
                write!(f, "export {context} RVA {rva:#x} is unmapped")
            }
            ExportError::InvalidString { offset } => {
                write!(
                    f,
                    "export string at offset {offset:#x} is not null-terminated"
                )
            }
        }
    }
}

impl fmt::Display for MappingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MappingError::BufferTooSmall { required, actual } => {
                write!(
                    f,
                    "mapping buffer too small: required {required}, actual {actual}"
                )
            }
            MappingError::RawDataExceedsFile {
                name,
                offset,
                size,
                file_len,
            } => {
                write!(f, "raw data for section '{name}' [{offset:#x}..{:#x}) exceeds file length {file_len:#x}",
                    offset.saturating_add(*size))
            }
            MappingError::RegionOutOfBounds { name, va, size } => {
                write!(
                    f,
                    "mapped region '{name}' at {va:#x} with size {size:#x} exceeds image span"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PeError {}

#[cfg(feature = "std")]
impl std::error::Error for RelocationError {}

#[cfg(feature = "std")]
impl std::error::Error for ImportError {}

#[cfg(feature = "std")]
impl std::error::Error for ExportError {}

#[cfg(feature = "std")]
impl std::error::Error for TlsError {}

#[cfg(feature = "std")]
impl std::error::Error for MappingError {}
