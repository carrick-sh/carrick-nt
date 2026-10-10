//! Typed memory mapping plan representation.
//!
//! Replaces raw u64s with typed VirtualAddress, VirtualRange, FileRange,
//! PageProtection, and structured regions, import bindings, and relocation deltas.
//!
//! Conforms to Microsoft PE and COFF Specification (Rev 11.0) Section 4 (Section Table)
//! and Section 3.4 (Optional Header).

use crate::error::MappingError;
use crate::headers::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE};
use crate::imports::ImportSymbol;
use crate::relocations::RelocationType;
use crate::tls::TlsDirectoryInfo;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// Strongly typed guest virtual address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct VirtualAddress(pub u64);

impl VirtualAddress {
    /// Zero virtual address.
    pub const NULL: Self = Self(0);

    /// Creates a new VirtualAddress.
    #[inline]
    pub const fn new(val: u64) -> Self {
        Self(val)
    }

    /// Returns the underlying u64 value.
    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Checked addition with a u64 offset.
    #[inline]
    pub fn checked_add(self, offset: u64) -> Option<Self> {
        self.0.checked_add(offset).map(Self)
    }

    /// Adds a signed delta to this address.
    #[inline]
    pub fn offset(self, delta: i64) -> Option<Self> {
        if delta >= 0 {
            self.0.checked_add(delta as u64).map(Self)
        } else {
            let abs = delta.unsigned_abs();
            self.0.checked_sub(abs).map(Self)
        }
    }

    /// Aligns this address up to the specified power-of-two alignment.
    #[inline]
    pub fn align_up(self, alignment: u64) -> Self {
        if alignment == 0 {
            return self;
        }
        let mask = alignment - 1;
        Self((self.0.saturating_add(mask)) & !mask)
    }

    /// Checks if this address is aligned to the specified power-of-two alignment.
    #[inline]
    pub fn is_aligned(self, alignment: u64) -> bool {
        if alignment == 0 {
            return true;
        }
        (self.0 & (alignment - 1)) == 0
    }
}

impl fmt::Debug for VirtualAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VA({:#018x})", self.0)
    }
}

impl fmt::Display for VirtualAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#018x}", self.0)
    }
}

/// A contiguous half-open virtual address range `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualRange {
    /// Beginning of the virtual range.
    pub start: VirtualAddress,
    /// Non-inclusive end of the virtual range.
    pub end: VirtualAddress,
}

impl VirtualRange {
    /// Constructs a virtual range from start and end.
    pub fn new(start: VirtualAddress, end: VirtualAddress) -> Result<Self, MappingError> {
        if start > end {
            return Err(MappingError::RegionOutOfBounds {
                name: String::from("<invalid>"),
                va: start.as_u64(),
                size: 0,
            });
        }
        Ok(Self { start, end })
    }

    /// Constructs a virtual range from start and size.
    pub fn from_start_size(start: VirtualAddress, size: u64) -> Result<Self, MappingError> {
        let end = start
            .checked_add(size)
            .ok_or(MappingError::RegionOutOfBounds {
                name: String::from("<overflow>"),
                va: start.as_u64(),
                size,
            })?;
        Ok(Self { start, end })
    }

    /// Returns the length in bytes of the virtual range.
    #[inline]
    pub fn len(&self) -> u64 {
        self.end.as_u64() - self.start.as_u64()
    }

    /// Returns true if the range length is 0.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Returns true if the address is within `[start, end)`.
    #[inline]
    pub fn contains(&self, va: VirtualAddress) -> bool {
        va >= self.start && va < self.end
    }

    /// Returns true if this range overlaps with another.
    #[inline]
    pub fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// A byte span in the source image file `[offset, offset + size)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileRange {
    /// File offset from start of image file.
    pub offset: u64,
    /// Size of the raw data in bytes.
    pub size: u64,
}

impl FileRange {
    /// Creates a new FileRange.
    #[inline]
    pub fn new(offset: u64, size: u64) -> Self {
        Self { offset, size }
    }

    /// Reads this file range as a byte slice from file data.
    pub fn as_slice<'a>(&self, bytes: &'a [u8]) -> Option<&'a [u8]> {
        let start = self.offset as usize;
        let end = start.checked_add(self.size as usize)?;
        if end <= bytes.len() {
            Some(&bytes[start..end])
        } else {
            None
        }
    }
}

/// Typed page protection attributes.
///
/// Derived from Section Characteristics per Microsoft PE Specification Section 4.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PageProtection {
    /// Read-only pages (e.g. PE headers, .rdata, .pdata, .reloc).
    ReadOnly,
    /// Read-write pages (e.g. .data, .bss).
    ReadWrite,
    /// Read-execute pages (e.g. .text code section).
    ReadExecute,
    /// Execute-read-write pages.
    ExecuteReadWrite,
    /// No access / guard page.
    NoAccess,
}

impl PageProtection {
    /// Derives PageProtection from PE section characteristics flags.
    ///
    /// Microsoft PE and COFF Specification (Rev 11.0) Section 4.1:
    /// - IMAGE_SCN_MEM_EXECUTE (0x20000000)
    /// - IMAGE_SCN_MEM_READ (0x40000000)
    /// - IMAGE_SCN_MEM_WRITE (0x80000000)
    pub fn from_characteristics(chars: u32) -> Self {
        let r = (chars & IMAGE_SCN_MEM_READ) != 0;
        let w = (chars & IMAGE_SCN_MEM_WRITE) != 0;
        let x = (chars & IMAGE_SCN_MEM_EXECUTE) != 0;

        match (r, w, x) {
            (true, true, true) => PageProtection::ExecuteReadWrite,
            (true, false, true) => PageProtection::ReadExecute,
            (true, true, false) => PageProtection::ReadWrite,
            (true, false, false) => PageProtection::ReadOnly,
            (false, true, false) => PageProtection::ReadWrite,
            (false, false, true) => PageProtection::ReadExecute,
            _ => PageProtection::NoAccess,
        }
    }

    /// Returns true if the page is readable.
    #[inline]
    pub fn is_readable(&self) -> bool {
        matches!(
            self,
            Self::ReadOnly | Self::ReadWrite | Self::ReadExecute | Self::ExecuteReadWrite
        )
    }

    /// Returns true if the page is writable.
    #[inline]
    pub fn is_writable(&self) -> bool {
        matches!(self, Self::ReadWrite | Self::ExecuteReadWrite)
    }

    /// Returns true if the page is executable.
    #[inline]
    pub fn is_executable(&self) -> bool {
        matches!(self, Self::ReadExecute | Self::ExecuteReadWrite)
    }
}

/// A planned memory region to be mapped into the address space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedRegion {
    /// Section name (e.g. "headers", ".text", ".rdata", ".data").
    pub name: String,
    /// Virtual address range reserved/committed for this region.
    pub virtual_range: VirtualRange,
    /// Source file range to copy into the beginning of the virtual range.
    pub file_range: Option<FileRange>,
    /// Number of bytes following the raw file data that must be zero-filled (.bss).
    pub zero_fill_len: u64,
    /// Memory protection required for these pages.
    pub protection: PageProtection,
}

/// A resolved import entry to be written to the Import Address Table (IAT).
///
/// Microsoft PE and COFF Specification (Rev 11.0) Section 6.4: The .idata Section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportBinding {
    /// Name of the imported DLL (e.g. "KERNEL32.dll").
    pub dll_name: String,
    /// The imported symbol (named function or ordinal).
    pub symbol: ImportSymbol,
    /// RVA within the image of the IAT slot.
    pub iat_rva: u32,
    /// Virtual address within the mapped image of the IAT slot.
    pub iat_va: VirtualAddress,
    /// Resolved target virtual address of the exported function.
    pub resolved_va: VirtualAddress,
}

/// A base relocation fixup applied when loaded at an address other than ImageBase.
///
/// Microsoft PE and COFF Specification (Rev 11.0) Section 6.6: The .reloc Section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocationDelta {
    /// RVA of the fixup location in the image.
    pub target_rva: u32,
    /// Virtual address where the relocation is applied.
    pub target_va: VirtualAddress,
    /// Type of relocation (e.g. DIR64 = 10).
    pub relocation_type: RelocationType,
    /// Delta added: `actual_base - preferred_image_base`.
    pub delta: i64,
    /// Original pointer value found at this target before relocation.
    pub original_value: u64,
    /// Adjusted pointer value after applying delta.
    pub relocated_value: u64,
}

/// Complete typed mapping plan for an executable PE image.
///
/// Can be verifiedVM-free, and later executed by Carrick CPL0 kernel seams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingPlan {
    /// Actual base virtual address where the image is planned to be mapped.
    pub image_base: VirtualAddress,
    /// Preferred ImageBase declared in the PE optional header.
    pub preferred_image_base: VirtualAddress,
    /// Absolute virtual address of the entry point.
    pub entry_point: VirtualAddress,
    /// Total virtual memory span in bytes (`OptionalHeader.SizeOfImage`).
    pub total_virtual_size: u64,
    /// Ordered list of mapped memory regions (headers + sections).
    pub regions: Vec<MappedRegion>,
    /// List of resolved import bindings to be written into the IAT.
    pub import_bindings: Vec<ImportBinding>,
    /// List of base relocations to be applied (empty if loaded at preferred ImageBase).
    pub relocations: Vec<RelocationDelta>,
    /// Thread Local Storage configuration if present.
    pub tls: Option<TlsDirectoryInfo>,
}

impl MappingPlan {
    /// Applies the mapping plan into a contiguous target memory buffer.
    ///
    /// This simulates Carrick guest memory initialization in host unit tests:
    /// 1. Verifies buffer size >= total_virtual_size.
    /// 2. Copies headers and each section's raw data.
    /// 3. Zeroes any uninitialized BSS spans.
    /// 4. Applies all base relocation fixups.
    /// 5. Writes resolved import addresses into their IAT slots.
    pub fn apply_to_buffer(
        &self,
        file_bytes: &[u8],
        target: &mut [u8],
    ) -> Result<(), MappingError> {
        let req_len = self.total_virtual_size as usize;
        if target.len() < req_len {
            return Err(MappingError::BufferTooSmall {
                required: req_len,
                actual: target.len(),
            });
        }

        // Initialize target with zeros
        target[..req_len].fill(0);

        // Copy regions
        for region in &self.regions {
            let reg_offset =
                (region.virtual_range.start.as_u64() - self.image_base.as_u64()) as usize;
            if let Some(file_range) = region.file_range {
                if file_range.size > 0 {
                    let src = file_range.as_slice(file_bytes).ok_or_else(|| {
                        MappingError::RawDataExceedsFile {
                            name: region.name.clone(),
                            offset: file_range.offset as u32,
                            size: file_range.size as u32,
                            file_len: file_bytes.len(),
                        }
                    })?;
                    let copy_len = src.len();
                    let dst_end = reg_offset.checked_add(copy_len).ok_or_else(|| {
                        MappingError::RegionOutOfBounds {
                            name: region.name.clone(),
                            va: region.virtual_range.start.as_u64(),
                            size: region.virtual_range.len(),
                        }
                    })?;
                    if dst_end > target.len() {
                        return Err(MappingError::BufferTooSmall {
                            required: dst_end,
                            actual: target.len(),
                        });
                    }
                    target[reg_offset..dst_end].copy_from_slice(src);
                }
            }
        }

        // Apply base relocations
        for reloc in &self.relocations {
            let offset = reloc.target_rva as usize;
            if offset + 8 > target.len() {
                return Err(MappingError::BufferTooSmall {
                    required: offset + 8,
                    actual: target.len(),
                });
            }
            let bytes = reloc.relocated_value.to_le_bytes();
            target[offset..offset + 8].copy_from_slice(&bytes);
        }

        // Write resolved IAT bindings
        for import in &self.import_bindings {
            let offset = import.iat_rva as usize;
            if offset + 8 > target.len() {
                return Err(MappingError::BufferTooSmall {
                    required: offset + 8,
                    actual: target.len(),
                });
            }
            let bytes = import.resolved_va.as_u64().to_le_bytes();
            target[offset..offset + 8].copy_from_slice(&bytes);
        }

        Ok(())
    }

    /// Finds a mapped region by section name.
    pub fn find_region_by_name(&self, name: &str) -> Option<&MappedRegion> {
        self.regions.iter().find(|r| r.name == name)
    }

    /// Finds the mapped region enclosing the specified virtual address.
    pub fn find_region_for_va(&self, va: VirtualAddress) -> Option<&MappedRegion> {
        self.regions.iter().find(|r| r.virtual_range.contains(va))
    }
}
