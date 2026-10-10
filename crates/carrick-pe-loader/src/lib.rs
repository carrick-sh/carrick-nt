//! Clean-room PE/COFF loader and memory mapping planner for Carrick NT.
//!
//! Conforms strictly to:
//! - Microsoft PE and COFF Specification (Rev 11.0)
//! - Microsoft Learn: x64 Software Conventions
//! - Microsoft Learn: Winternl.h (PEB, TEB, RTL_USER_PROCESS_PARAMETERS)
//!
//! Provides a pure, host-testable library (VM-free) that:
//! 1. Parses and validates DOS, COFF, Optional PE32+, and Section headers.
//! 2. Plans section mappings with typed PageProtection, VirtualAddress, and alignment.
//! 3. Evaluates and applies base relocations (.reloc) for dynamic base / ASLR binaries.
//! 4. Resolves imports against a pluggable ExportProvider (with stub providers for testing).
//! 5. Parses Thread Local Storage (.tls) directories and callbacks.
//! 6. Constructs initial user-mode runtime memory structures (TEB, PEB, Process Parameters).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod error;
pub mod headers;
pub mod imports;
pub mod mapper;
pub mod plan;
pub mod process_memory;
pub mod relocations;
pub mod tls;

// Re-export primary types for ease of use
pub use error::{ImportError, MappingError, PeError, RelocationError, TlsError};
pub use headers::{
    DataDirectory, DosHeader, OptionalHeader64, PeHeaders, SectionHeader, IMAGE_DOS_SIGNATURE,
    IMAGE_FILE_MACHINE_AMD64, IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_NT_SIGNATURE,
    IMAGE_SUBSYSTEM_WINDOWS_CUI,
};
pub use imports::{ExportProvider, ImportSymbol, StubExportProvider};
pub use mapper::PeLoader;
pub use plan::{
    FileRange, ImportBinding, MappedRegion, MappingPlan, PageProtection, RelocationDelta,
    VirtualAddress, VirtualRange,
};
pub use process_memory::{
    ProcessMemoryConfig, ProcessMemoryImage, STD_ERROR_HANDLE_VAL, STD_INPUT_HANDLE_VAL,
    STD_OUTPUT_HANDLE_VAL, TEB_OFFSET_CLIENT_ID, TEB_OFFSET_PEB, TEB_OFFSET_SELF,
};
pub use relocations::{BaseRelocationBlock, RelocationType};
pub use tls::TlsDirectoryInfo;
