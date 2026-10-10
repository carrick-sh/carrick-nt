//! Clean-room NT wire structure definitions with stable `repr(C)` layouts.
//!
//! Citations:
//! - Microsoft Learn: `IO_STATUS_BLOCK` (WDK)
//!   https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_status_block
//! - Microsoft Learn: `UNICODE_STRING` (Subauth)
//!   https://learn.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-unicode_string
//! - Microsoft Learn: `OBJECT_ATTRIBUTES` (WDK)
//!   https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes
//! - Microsoft Learn: `CLIENT_ID` (Winternl.h)
//!   https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb

use crate::handle::NtHandle;
use crate::pointer::GuestVa;
use crate::status::NtStatus;
use core::mem::{align_of, offset_of, size_of};

/// Clean-room NT `IO_STATUS_BLOCK` wire structure.
///
/// On x86_64 Windows:
/// - Offset 0: `Status` (NTSTATUS, 4 bytes)
/// - Offset 4: Padding (4 bytes)
/// - Offset 8: `Information` (ULONG_PTR, 8 bytes)
/// - Size: 16 bytes, Align: 8 bytes
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct IoStatusBlock {
    /// Completion status of the I/O operation.
    pub status: NtStatus,
    /// Explicit padding aligning `information` to 8 bytes.
    pub _padding: u32,
    /// Number of bytes transferred or request-dependent status information.
    pub information: u64,
}

impl IoStatusBlock {
    /// Creates a new successful `IoStatusBlock` with the given transferred byte count.
    #[inline]
    pub const fn success(bytes_transferred: u64) -> Self {
        Self {
            status: NtStatus::STATUS_SUCCESS,
            _padding: 0,
            information: bytes_transferred,
        }
    }

    /// Creates an `IoStatusBlock` reporting an error status code.
    #[inline]
    pub const fn error(status: NtStatus) -> Self {
        Self {
            status,
            _padding: 0,
            information: 0,
        }
    }
}

/// Clean-room NT `UNICODE_STRING` wire structure.
///
/// On x86_64 Windows:
/// - Offset 0: `Length` (USHORT, 2 bytes)
/// - Offset 2: `MaximumLength` (USHORT, 2 bytes)
/// - Offset 4: Padding (4 bytes)
/// - Offset 8: `Buffer` (PWSTR, 8 bytes)
/// - Size: 16 bytes, Align: 8 bytes
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct UnicodeString {
    /// Length of the string in bytes (not UTF-16 code units), excluding any null terminator.
    pub length: u16,
    /// Total allocation size of the buffer in bytes.
    pub maximum_length: u16,
    /// Explicit padding aligning `buffer` to 8 bytes.
    pub _padding: u32,
    /// Guest virtual address of the UTF-16 buffer.
    pub buffer: GuestVa,
}

impl UnicodeString {
    /// Creates an empty `UnicodeString`.
    #[inline]
    pub const fn empty() -> Self {
        Self {
            length: 0,
            maximum_length: 0,
            _padding: 0,
            buffer: GuestVa::NULL,
        }
    }

    /// Creates a `UnicodeString` with explicit length, capacity, and buffer pointer.
    #[inline]
    pub const fn new(length: u16, maximum_length: u16, buffer: GuestVa) -> Self {
        Self {
            length,
            maximum_length,
            _padding: 0,
            buffer,
        }
    }
}

/// Clean-room NT `OBJECT_ATTRIBUTES` wire structure.
///
/// On x86_64 Windows:
/// - Offset 0: `Length` (ULONG, 4 bytes)
/// - Offset 4: Padding (4 bytes)
/// - Offset 8: `RootDirectory` (HANDLE, 8 bytes)
/// - Offset 16: `ObjectName` (PUNICODE_STRING, 8 bytes)
/// - Offset 24: `Attributes` (ULONG, 4 bytes)
/// - Offset 28: Padding (4 bytes)
/// - Offset 32: `SecurityDescriptor` (PVOID, 8 bytes)
/// - Offset 40: `SecurityQualityOfService` (PVOID, 8 bytes)
/// - Size: 48 bytes, Align: 8 bytes
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ObjectAttributes {
    /// Size of this structure in bytes (must be 48 on x86_64).
    pub length: u32,
    /// Explicit padding aligning `root_directory` to 8 bytes.
    pub _padding1: u32,
    /// Optional root directory handle for relative path opens.
    pub root_directory: NtHandle,
    /// Guest virtual address of `UnicodeString` object path.
    pub object_name: GuestVa,
    /// Object attribute flags (OBJ_CASE_INSENSITIVE, OBJ_INHERIT, etc.).
    pub attributes: u32,
    /// Explicit padding aligning `security_descriptor` to 8 bytes.
    pub _padding2: u32,
    /// Optional security descriptor pointer.
    pub security_descriptor: GuestVa,
    /// Optional security quality-of-service pointer.
    pub security_quality_of_service: GuestVa,
}

impl ObjectAttributes {
    /// Creates a minimal `ObjectAttributes` specifying only an object name.
    #[inline]
    pub const fn with_name(object_name: GuestVa, attributes: u32) -> Self {
        Self {
            length: size_of::<Self>() as u32,
            _padding1: 0,
            root_directory: NtHandle::NULL,
            object_name,
            attributes,
            _padding2: 0,
            security_descriptor: GuestVa::NULL,
            security_quality_of_service: GuestVa::NULL,
        }
    }
}

/// Clean-room NT `CLIENT_ID` wire structure.
///
/// On x86_64 Windows:
/// - Offset 0: `UniqueProcess` (HANDLE, 8 bytes)
/// - Offset 8: `UniqueThread` (HANDLE, 8 bytes)
/// - Size: 16 bytes, Align: 8 bytes
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientId {
    /// Process identifier (PID) represented as an NT handle.
    pub unique_process: NtHandle,
    /// Thread identifier (TID) represented as an NT handle.
    pub unique_thread: NtHandle,
}

impl ClientId {
    /// Creates a `ClientId` from numeric process and thread identifiers.
    #[inline]
    pub const fn new(pid: u64, tid: u64) -> Self {
        Self {
            unique_process: NtHandle::from_raw(pid),
            unique_thread: NtHandle::from_raw(tid),
        }
    }
}

// ============================================================================
// Compile-Time Size, Alignment, and Offset Assertions (x86_64 NT ABI)
// ============================================================================

const _: () = {
    // IO_STATUS_BLOCK
    assert!(size_of::<IoStatusBlock>() == 16);
    assert!(align_of::<IoStatusBlock>() == 8);
    assert!(offset_of!(IoStatusBlock, status) == 0);
    assert!(offset_of!(IoStatusBlock, information) == 8);

    // UNICODE_STRING
    assert!(size_of::<UnicodeString>() == 16);
    assert!(align_of::<UnicodeString>() == 8);
    assert!(offset_of!(UnicodeString, length) == 0);
    assert!(offset_of!(UnicodeString, maximum_length) == 2);
    assert!(offset_of!(UnicodeString, buffer) == 8);

    // OBJECT_ATTRIBUTES
    assert!(size_of::<ObjectAttributes>() == 48);
    assert!(align_of::<ObjectAttributes>() == 8);
    assert!(offset_of!(ObjectAttributes, length) == 0);
    assert!(offset_of!(ObjectAttributes, root_directory) == 8);
    assert!(offset_of!(ObjectAttributes, object_name) == 16);
    assert!(offset_of!(ObjectAttributes, attributes) == 24);
    assert!(offset_of!(ObjectAttributes, security_descriptor) == 32);
    assert!(offset_of!(ObjectAttributes, security_quality_of_service) == 40);

    // CLIENT_ID
    assert!(size_of::<ClientId>() == 16);
    assert!(align_of::<ClientId>() == 8);
    assert!(offset_of!(ClientId, unique_process) == 0);
    assert!(offset_of!(ClientId, unique_thread) == 8);
};
