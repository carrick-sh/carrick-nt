//! Carrick kernel user-memory adapter for carrick-personality-nt.
//!
//! Citations:
//! - docs/design/ntdll-bootstrap.md Section 2.3 & 4.2
//! - Microsoft Learn: WDK Native APIs & Virtual Memory Access
//! - AGENTS.md clean-room rules: 100% clean-room, no Wine/ReactOS, no leaked Microsoft code.

use carrick_core::personality::{ServiceError, UserMemory as CarrickCoreUserMemory};
use carrick_guest_arch::{DefaultMmOwner, GuestLen, MmuArch, UserRange, UserVa};
use carrick_nt_abi::{GuestVa, NtStatus};

use crate::memory::UserMemory;

/// Maps a Carrick `ServiceError` from guest user-memory access into the corresponding `NtStatus`.
///
/// In the Windows NT kernel, unmapped addresses, memory protection violations (writing to
/// read-only pages), and user range violations (overflows outside canonical lower-half)
/// raise access violations (`STATUS_ACCESS_VIOLATION`). Unbound or unsupported operational
/// refusals map to `STATUS_UNSUCCESSFUL`.
pub const fn service_error_to_ntstatus(err: ServiceError) -> NtStatus {
    match err {
        ServiceError::Fault => NtStatus::STATUS_ACCESS_VIOLATION,
        ServiceError::AccessDenied => NtStatus::STATUS_ACCESS_VIOLATION,
        ServiceError::RangeOverflow => NtStatus::STATUS_ACCESS_VIOLATION,
        ServiceError::Refused => NtStatus::STATUS_UNSUCCESSFUL,
    }
}

/// Constructs a validated `UserRange` from guest virtual address and byte length.
#[inline]
fn user_range(va: GuestVa, len: usize) -> Result<UserRange, NtStatus> {
    UserRange::checked(UserVa::new(va.as_u64()), GuestLen::new(len as u64))
        .ok_or(NtStatus::STATUS_ACCESS_VIOLATION)
}

impl<'a, A: MmuArch + DefaultMmOwner> UserMemory for CarrickCoreUserMemory<'a, A>
where
    ServiceError: From<A::Error>,
{
    fn read_bytes(&mut self, va: GuestVa, buf: &mut [u8]) -> Result<(), NtStatus> {
        if buf.is_empty() {
            return Ok(());
        }
        let range = user_range(va, buf.len())?;
        self.copy_in(range, buf)
            .map_err(service_error_to_ntstatus)?;
        Ok(())
    }

    fn write_bytes(&mut self, va: GuestVa, buf: &[u8]) -> Result<(), NtStatus> {
        if buf.is_empty() {
            return Ok(());
        }
        let range = user_range(va, buf.len())?;
        self.copy_out(range, buf)
            .map_err(service_error_to_ntstatus)?;
        Ok(())
    }
}
