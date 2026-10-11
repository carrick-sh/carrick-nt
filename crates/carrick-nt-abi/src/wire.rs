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

/// Clean-room NT `CURDIR` wire structure representing the current directory.
///
/// On x86_64 Windows:
/// - Offset 0: `DosPath` (`UNICODE_STRING`, 16 bytes)
/// - Offset 16: `Handle` (`NtHandle`, 8 bytes)
/// - Size: 24 bytes, Align: 8 bytes
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CurDir {
    pub dos_path: UnicodeString,
    pub handle: NtHandle,
}

impl CurDir {
    /// Creates an empty `CurDir`.
    #[inline]
    pub const fn empty() -> Self {
        Self {
            dos_path: UnicodeString::empty(),
            handle: NtHandle::NULL,
        }
    }
}

/// Clean-room NT `RTL_USER_PROCESS_PARAMETERS` wire structure.
///
/// Citations:
/// - Microsoft Learn: RTL_USER_PROCESS_PARAMETERS (winternl.h)
///   https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-rtl_user_process_parameters
///
/// On x86_64 Windows:
/// - Offset 0x00: `MaximumLength` (ULONG, 4 bytes)
/// - Offset 0x04: `Length` (ULONG, 4 bytes)
/// - Offset 0x08: `Flags` (ULONG, 4 bytes)
/// - Offset 0x0C: `DebugFlags` (ULONG, 4 bytes)
/// - Offset 0x10: `ConsoleHandle` (HANDLE, 8 bytes)
/// - Offset 0x18: `ConsoleFlags` (ULONG_PTR, 8 bytes)
/// - Offset 0x20: `StandardInput` (HANDLE, 8 bytes)
/// - Offset 0x28: `StandardOutput` (HANDLE, 8 bytes)
/// - Offset 0x30: `StandardError` (HANDLE, 8 bytes)
/// - Offset 0x38: `CurrentDirectory` (CURDIR, 24 bytes)
/// - Offset 0x50: `DllPath` (UNICODE_STRING, 16 bytes)
/// - Offset 0x60: `ImagePathName` (UNICODE_STRING, 16 bytes)
/// - Offset 0x70: `CommandLine` (UNICODE_STRING, 16 bytes)
/// - Offset 0x80: `Environment` (PVOID, 8 bytes)
/// - Total size: 136 bytes (0x88), Align: 8 bytes
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RtlUserProcessParameters {
    pub maximum_length: u32,
    pub length: u32,
    pub flags: u32,
    pub debug_flags: u32,
    pub console_handle: NtHandle,
    pub console_flags: u64,
    pub standard_input: NtHandle,
    pub standard_output: NtHandle,
    pub standard_error: NtHandle,
    pub current_directory: CurDir,
    pub dll_path: UnicodeString,
    pub image_path_name: UnicodeString,
    pub command_line: UnicodeString,
    pub environment: GuestVa,
}

/// Clean-room NT `PEB` (Process Environment Block) wire structure prefix.
///
/// Citations:
/// - Microsoft Learn: PEB structure (winternl.h)
///   https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb
///
/// On x86_64 Windows:
/// - Offset 0x00: `Reserved1` (BYTE[2], 2 bytes)
/// - Offset 0x02: `BeingDebugged` (BYTE, 1 byte)
/// - Offset 0x03: `Reserved2` (BYTE[1], 1 byte)
/// - Offset 0x04: Padding (4 bytes)
/// - Offset 0x08: `Mutant` (PVOID, 8 bytes)
/// - Offset 0x10: `ImageBaseAddress` (PVOID, 8 bytes)
/// - Offset 0x18: `LoaderData` (PVOID, 8 bytes)
/// - Offset 0x20: `ProcessParameters` (PVOID / PRTL_USER_PROCESS_PARAMETERS, 8 bytes)
/// - Size: 40 bytes (0x28), Align: 8 bytes
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Peb {
    pub reserved1: [u8; 2],
    pub being_debugged: u8,
    pub reserved2: [u8; 1],
    pub _padding: u32,
    pub mutant: GuestVa,
    pub image_base_address: GuestVa,
    pub loader_data: GuestVa,
    pub process_parameters: GuestVa,
}

/// Clean-room NT `TEB` (Thread Environment Block) wire structure prefix.
///
/// Citations:
/// - Microsoft Learn: TEB structure (winternl.h)
///   https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb
///
/// On x86_64 Windows:
/// - Offset 0x00: `Reserved1` (PVOID[6], 48 bytes)
/// - Offset 0x30: `Self` (PVOID, 8 bytes)
/// - Offset 0x38: `ReservedSubsystem` (PVOID, 8 bytes)
/// - Offset 0x40: `ClientId` (CLIENT_ID, 16 bytes: PID at 0x40, TID at 0x48)
/// - Offset 0x50: `ReservedRpc` (PVOID, 8 bytes)
/// - Offset 0x58: `ReservedTls` (PVOID, 8 bytes)
/// - Offset 0x60: `ProcessEnvironmentBlock` (PPEB, 8 bytes)
/// - Size: 104 bytes (0x68), Align: 8 bytes
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Teb {
    pub reserved1: [GuestVa; 6],
    pub teb_self: GuestVa,
    pub reserved_subsystem: GuestVa,
    pub client_id: ClientId,
    pub reserved_rpc: GuestVa,
    pub reserved_tls: GuestVa,
    pub process_environment_block: GuestVa,
}

/// Searches a double-null-terminated UTF-16 environment block for a variable by name.
///
/// The comparison is case-insensitive for ASCII letters per Windows standard behavior.
/// Returns `Some(&[u16])` with the variable's value (excluding terminating null) if found,
/// or `None` if not present.
pub fn find_environment_variable<'a>(env_block: &'a [u16], name: &[u16]) -> Option<&'a [u16]> {
    if name.is_empty() || env_block.is_empty() {
        return None;
    }

    let mut offset = 0;
    while offset < env_block.len() && env_block[offset] != 0 {
        let start = offset;
        while offset < env_block.len() && env_block[offset] != 0 {
            offset += 1;
        }
        let entry = &env_block[start..offset];
        if offset < env_block.len() {
            offset += 1; // skip null terminator of current entry
        }

        // In Windows, an entry can start with '=' for drive-letter hidden variables (e.g. "=C:=C:\dir")
        // We search for '=' after index 0.
        if let Some(eq_pos) = entry
            .iter()
            .enumerate()
            .position(|(i, &c)| i > 0 && c == b'=' as u16)
        {
            let var_name = &entry[..eq_pos];
            let var_val = &entry[eq_pos + 1..];

            if eq_ignore_ascii_case_utf16(var_name, name) {
                return Some(var_val);
            }
        }
    }

    None
}

/// Case-insensitive ASCII equality comparison for UTF-16 slices.
pub fn eq_ignore_ascii_case_utf16(a: &[u16], b: &[u16]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for (&x, &y) in a.iter().zip(b.iter()) {
        let x_norm = if (b'a' as u16..=b'z' as u16).contains(&x) {
            x - 32
        } else {
            x
        };
        let y_norm = if (b'a' as u16..=b'z' as u16).contains(&y) {
            y - 32
        } else {
            y
        };
        if x_norm != y_norm {
            return false;
        }
    }
    true
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

    // CURDIR
    assert!(size_of::<CurDir>() == 24);
    assert!(align_of::<CurDir>() == 8);
    assert!(offset_of!(CurDir, dos_path) == 0);
    assert!(offset_of!(CurDir, handle) == 16);

    // RTL_USER_PROCESS_PARAMETERS
    assert!(size_of::<RtlUserProcessParameters>() == 136);
    assert!(align_of::<RtlUserProcessParameters>() == 8);
    assert!(offset_of!(RtlUserProcessParameters, maximum_length) == 0);
    assert!(offset_of!(RtlUserProcessParameters, length) == 4);
    assert!(offset_of!(RtlUserProcessParameters, flags) == 8);
    assert!(offset_of!(RtlUserProcessParameters, debug_flags) == 12);
    assert!(offset_of!(RtlUserProcessParameters, console_handle) == 16);
    assert!(offset_of!(RtlUserProcessParameters, console_flags) == 24);
    assert!(offset_of!(RtlUserProcessParameters, standard_input) == 32);
    assert!(offset_of!(RtlUserProcessParameters, standard_output) == 40);
    assert!(offset_of!(RtlUserProcessParameters, standard_error) == 48);
    assert!(offset_of!(RtlUserProcessParameters, current_directory) == 56);
    assert!(offset_of!(RtlUserProcessParameters, dll_path) == 80);
    assert!(offset_of!(RtlUserProcessParameters, image_path_name) == 96);
    assert!(offset_of!(RtlUserProcessParameters, command_line) == 112);
    assert!(offset_of!(RtlUserProcessParameters, environment) == 128);

    // PEB
    assert!(size_of::<Peb>() == 40);
    assert!(align_of::<Peb>() == 8);
    assert!(offset_of!(Peb, being_debugged) == 2);
    assert!(offset_of!(Peb, mutant) == 8);
    assert!(offset_of!(Peb, image_base_address) == 16);
    assert!(offset_of!(Peb, loader_data) == 24);
    assert!(offset_of!(Peb, process_parameters) == 32);

    // TEB
    assert!(size_of::<Teb>() == 104);
    assert!(align_of::<Teb>() == 8);
    assert!(offset_of!(Teb, teb_self) == 48);
    assert!(offset_of!(Teb, client_id) == 64);
    assert!(offset_of!(Teb, process_environment_block) == 96);
};
