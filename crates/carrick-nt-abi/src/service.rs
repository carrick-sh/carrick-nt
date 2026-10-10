//! Carrick NT system call service identifiers.
//!
//! Citations:
//! - docs/design/ntdll-bootstrap.md Section 2.3: "The Carrick NT Hypercall / System Call Contract"
//! - docs/design/ntdll-bootstrap.md Section 6.4: "Work Package NT-008"

use core::fmt;

/// Carrick NT system call service identifier.
///
/// In Carrick's NT userland, system service numbers are stable, sequential
/// identifiers passed in `eax` during the x86_64 `syscall` instruction.
///
/// Clean-Room Policy: These are proprietary to Carrick's NT personality contract
/// and deliberately do NOT mimic volatile Windows kernel build numbers.
#[repr(u32)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NtServiceId {
    /// Terminates the specified process and all its threads (`NtTerminateProcess`).
    NtTerminateProcess = 1,
    /// Writes data to an open file or device stream (`NtWriteFile`).
    NtWriteFile = 2,
    /// Closes an open object handle (`NtClose`).
    NtClose = 3,
}

impl NtServiceId {
    /// Converts a raw 32-bit integer into a valid `NtServiceId`, or `None` if invalid.
    #[inline]
    pub const fn from_u32(val: u32) -> Option<Self> {
        match val {
            1 => Some(Self::NtTerminateProcess),
            2 => Some(Self::NtWriteFile),
            3 => Some(Self::NtClose),
            _ => None,
        }
    }

    /// Returns the numeric service identifier as `u32`.
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

impl fmt::Debug for NtServiceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NtTerminateProcess => write!(f, "NtTerminateProcess (1)"),
            Self::NtWriteFile => write!(f, "NtWriteFile (2)"),
            Self::NtClose => write!(f, "NtClose (3)"),
        }
    }
}

impl fmt::Display for NtServiceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NtTerminateProcess => write!(f, "NtTerminateProcess"),
            Self::NtWriteFile => write!(f, "NtWriteFile"),
            Self::NtClose => write!(f, "NtClose"),
        }
    }
}

impl TryFrom<u32> for NtServiceId {
    type Error = ();

    #[inline]
    fn try_from(val: u32) -> Result<Self, Self::Error> {
        Self::from_u32(val).ok_or(())
    }
}

impl From<NtServiceId> for u32 {
    #[inline]
    fn from(id: NtServiceId) -> Self {
        id.as_u32()
    }
}
