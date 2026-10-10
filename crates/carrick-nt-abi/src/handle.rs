//! NT handle typed domain newtype.
//!
//! Conforms to Microsoft NT handle conventions and Carrick typed-domain rules.

use core::fmt;

/// NT object handle typed newtype.
///
/// On x86_64, NT handles are 64-bit opaque values (`HANDLE` / `PVOID`).
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct NtHandle(pub u64);

impl NtHandle {
    /// NULL handle (0x0).
    pub const NULL: Self = Self(0);

    /// INVALID_HANDLE_VALUE (-1 as u64).
    pub const INVALID: Self = Self(0xFFFF_FFFF_FFFF_FFFF);

    /// Current process pseudo-handle (NtCurrentProcess, -1 as u64).
    pub const CURRENT_PROCESS: Self = Self(0xFFFF_FFFF_FFFF_FFFF);

    /// Current thread pseudo-handle (NtCurrentThread, -2 as u64).
    pub const CURRENT_THREAD: Self = Self(0xFFFF_FFFF_FFFF_FFFE);

    /// Standard Input pseudo-handle (STD_INPUT_HANDLE, -10 as u64).
    pub const STD_INPUT: Self = Self(0xFFFF_FFFF_FFFF_FFF6);

    /// Standard Output pseudo-handle (STD_OUTPUT_HANDLE, -11 as u64).
    pub const STD_OUTPUT: Self = Self(0xFFFF_FFFF_FFFF_FFF5);

    /// Standard Error pseudo-handle (STD_ERROR_HANDLE, -12 as u64).
    pub const STD_ERROR: Self = Self(0xFFFF_FFFF_FFFF_FFF4);

    /// Creates an `NtHandle` from a raw 64-bit value.
    #[inline]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the raw 64-bit handle value.
    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Returns the handle as a signed pointer-sized integer.
    #[inline]
    pub const fn as_isize(self) -> isize {
        self.0 as isize
    }

    /// Returns `true` if this handle is null (0).
    #[inline]
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }

    /// Returns `true` if this handle equals `INVALID_HANDLE_VALUE` or `NULL`.
    #[inline]
    pub const fn is_invalid(self) -> bool {
        self.0 == 0 || self.0 == Self::INVALID.0
    }

    /// Returns `true` if this handle is a pseudo-handle (such as `CURRENT_PROCESS`).
    #[inline]
    pub const fn is_pseudo(self) -> bool {
        (self.0 as i64) < 0
    }
}

impl fmt::Debug for NtHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if *self == Self::CURRENT_PROCESS {
            write!(f, "NtHandle(CURRENT_PROCESS)")
        } else if *self == Self::CURRENT_THREAD {
            write!(f, "NtHandle(CURRENT_THREAD)")
        } else if *self == Self::STD_INPUT {
            write!(f, "NtHandle(STD_INPUT)")
        } else if *self == Self::STD_OUTPUT {
            write!(f, "NtHandle(STD_OUTPUT)")
        } else if *self == Self::STD_ERROR {
            write!(f, "NtHandle(STD_ERROR)")
        } else if *self == Self::NULL {
            write!(f, "NtHandle(NULL)")
        } else {
            write!(f, "NtHandle(0x{:016X})", self.0)
        }
    }
}

impl fmt::Display for NtHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:016X}", self.0)
    }
}

impl From<u64> for NtHandle {
    #[inline]
    fn from(val: u64) -> Self {
        Self(val)
    }
}

impl From<NtHandle> for u64 {
    #[inline]
    fn from(handle: NtHandle) -> Self {
        handle.0
    }
}
