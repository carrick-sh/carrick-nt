//! NTSTATUS typed domain newtype and standard NT status codes.
//!
//! Citations:
//! - Microsoft Learn: [NTSTATUS values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/87f04b9f-0975-4277-a629-87f667db8a00)
//! - Microsoft WDK: `ntstatus.h`

use core::fmt;

/// NTSTATUS status code typed newtype.
///
/// In the Windows NT architecture, NTSTATUS is a 32-bit signed integer where:
/// - Bit 31..30: Severity (00 = Success, 01 = Informational, 10 = Warning, 11 = Error)
/// - Bit 29: Customer / Microsoft flag (0 = Microsoft, 1 = Customer)
/// - Bit 28: Reserved
/// - Bit 27..16: Facility
/// - Bit 15..0: Code
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct NtStatus(pub u32);

impl NtStatus {
    /// STATUS_SUCCESS (0x00000000): The operation completed successfully.
    pub const STATUS_SUCCESS: Self = Self(0x0000_0000);

    /// STATUS_UNSUCCESSFUL (0xC0000001): The requested operation was unsuccessful.
    pub const STATUS_UNSUCCESSFUL: Self = Self(0xC000_0001);

    /// STATUS_NOT_IMPLEMENTED (0xC0000002): The requested operation is not implemented.
    pub const STATUS_NOT_IMPLEMENTED: Self = Self(0xC000_0002);

    /// STATUS_ACCESS_VIOLATION (0xC0000005): The instruction at 0x%p referenced memory at 0x%p. The memory could not be %s.
    pub const STATUS_ACCESS_VIOLATION: Self = Self(0xC000_0005);

    /// STATUS_INVALID_HANDLE (0xC0000008): An invalid handle was specified.
    pub const STATUS_INVALID_HANDLE: Self = Self(0xC000_0008);

    /// STATUS_INVALID_PARAMETER (0xC000000D): An invalid parameter was passed.
    pub const STATUS_INVALID_PARAMETER: Self = Self(0xC000_000D);

    /// STATUS_END_OF_FILE (0xC0000011): The end-of-file marker was reached.
    pub const STATUS_END_OF_FILE: Self = Self(0xC000_0011);

    /// STATUS_ACCESS_DENIED (0xC0000022): Access is denied.
    pub const STATUS_ACCESS_DENIED: Self = Self(0xC000_0022);

    /// STATUS_BUFFER_TOO_SMALL (0xC0000023): The specified buffer is too small.
    pub const STATUS_BUFFER_TOO_SMALL: Self = Self(0xC000_0023);

    /// STATUS_OBJECT_TYPE_MISMATCH (0xC0000024): There is a mismatch between the type of object required by the requested operation and the type of object that is specified in the request.
    pub const STATUS_OBJECT_TYPE_MISMATCH: Self = Self(0xC000_0024);

    /// STATUS_OBJECT_NAME_NOT_FOUND (0xC0000034): The object name does not exist.
    pub const STATUS_OBJECT_NAME_NOT_FOUND: Self = Self(0xC000_0034);

    /// Creates an `NtStatus` from a raw `u32`.
    #[inline]
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw status code as `u32`.
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Returns the status code as a signed 32-bit integer (`i32`), matching native NTSTATUS.
    #[inline]
    pub const fn as_i32(self) -> i32 {
        self.0 as i32
    }

    /// Returns `true` if this status indicates success (Severity 0 or positive signed value).
    ///
    /// Corresponds to standard macro `NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)`.
    #[inline]
    pub const fn is_success(self) -> bool {
        self.as_i32() >= 0
    }

    /// Returns `true` if this status code represents an error (Severity 11b, bit 31 set).
    #[inline]
    pub const fn is_error(self) -> bool {
        (self.0 >> 30) == 3
    }

    /// Returns `true` if this status code represents a warning (Severity 10b).
    #[inline]
    pub const fn is_warning(self) -> bool {
        (self.0 >> 30) == 2
    }

    /// Returns `true` if this status code represents informational status (Severity 01b).
    #[inline]
    pub const fn is_informational(self) -> bool {
        (self.0 >> 30) == 1
    }
}

impl fmt::Debug for NtStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::STATUS_SUCCESS => write!(f, "STATUS_SUCCESS (0x{:08X})", self.0),
            Self::STATUS_UNSUCCESSFUL => write!(f, "STATUS_UNSUCCESSFUL (0x{:08X})", self.0),
            Self::STATUS_NOT_IMPLEMENTED => write!(f, "STATUS_NOT_IMPLEMENTED (0x{:08X})", self.0),
            Self::STATUS_ACCESS_VIOLATION => {
                write!(f, "STATUS_ACCESS_VIOLATION (0x{:08X})", self.0)
            }
            Self::STATUS_INVALID_HANDLE => write!(f, "STATUS_INVALID_HANDLE (0x{:08X})", self.0),
            Self::STATUS_INVALID_PARAMETER => {
                write!(f, "STATUS_INVALID_PARAMETER (0x{:08X})", self.0)
            }
            Self::STATUS_END_OF_FILE => write!(f, "STATUS_END_OF_FILE (0x{:08X})", self.0),
            Self::STATUS_ACCESS_DENIED => write!(f, "STATUS_ACCESS_DENIED (0x{:08X})", self.0),
            Self::STATUS_BUFFER_TOO_SMALL => {
                write!(f, "STATUS_BUFFER_TOO_SMALL (0x{:08X})", self.0)
            }
            Self::STATUS_OBJECT_TYPE_MISMATCH => {
                write!(f, "STATUS_OBJECT_TYPE_MISMATCH (0x{:08X})", self.0)
            }
            Self::STATUS_OBJECT_NAME_NOT_FOUND => {
                write!(f, "STATUS_OBJECT_NAME_NOT_FOUND (0x{:08X})", self.0)
            }
            _ => write!(f, "NtStatus(0x{:08X})", self.0),
        }
    }
}

impl fmt::Display for NtStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08X}", self.0)
    }
}

impl From<u32> for NtStatus {
    #[inline]
    fn from(val: u32) -> Self {
        Self(val)
    }
}

impl From<NtStatus> for u32 {
    #[inline]
    fn from(status: NtStatus) -> Self {
        status.0
    }
}
