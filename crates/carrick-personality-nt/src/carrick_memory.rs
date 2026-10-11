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

/// Adapter implementing the NT personality `UserMemory` port trait over Carrick's
/// personality-facing user copy handle (`carrick_core::personality::UserMemory`).
pub struct CarrickUserMemory<'a, A: MmuArch> {
    inner: CarrickCoreUserMemory<'a, A>,
}

impl<'a, A: MmuArch> CarrickUserMemory<'a, A> {
    /// Creates a new `CarrickUserMemory` adapter wrapping Carrick's `UserMemory` handle.
    pub fn new(inner: CarrickCoreUserMemory<'a, A>) -> Self {
        Self { inner }
    }

    /// Accesses the underlying Carrick user memory handle.
    pub fn inner(&self) -> &CarrickCoreUserMemory<'a, A> {
        &self.inner
    }

    /// Mutably accesses the underlying Carrick user memory handle.
    pub fn inner_mut(&mut self) -> &mut CarrickCoreUserMemory<'a, A> {
        &mut self.inner
    }

    /// Unwraps the adapter, returning the inner Carrick user memory handle.
    pub fn into_inner(self) -> CarrickCoreUserMemory<'a, A> {
        self.inner
    }
}

impl<'a, A: MmuArch> From<CarrickCoreUserMemory<'a, A>> for CarrickUserMemory<'a, A> {
    fn from(inner: CarrickCoreUserMemory<'a, A>) -> Self {
        Self::new(inner)
    }
}

impl<'a, A: MmuArch + DefaultMmOwner> UserMemory for CarrickUserMemory<'a, A>
where
    ServiceError: From<A::Error>,
{
    fn read_bytes(&mut self, va: GuestVa, buf: &mut [u8]) -> Result<(), NtStatus> {
        if buf.is_empty() {
            return Ok(());
        }
        let range = UserRange::checked(UserVa::new(va.as_u64()), GuestLen::new(buf.len() as u64))
            .ok_or(NtStatus::STATUS_ACCESS_VIOLATION)?;
        self.inner
            .copy_in(range, buf)
            .map_err(service_error_to_ntstatus)?;
        Ok(())
    }

    fn write_bytes(&mut self, va: GuestVa, buf: &[u8]) -> Result<(), NtStatus> {
        if buf.is_empty() {
            return Ok(());
        }
        let range = UserRange::checked(UserVa::new(va.as_u64()), GuestLen::new(buf.len() as u64))
            .ok_or(NtStatus::STATUS_ACCESS_VIOLATION)?;
        self.inner
            .copy_out(range, buf)
            .map_err(service_error_to_ntstatus)?;
        Ok(())
    }
}

impl<'a, A: MmuArch + DefaultMmOwner> UserMemory for CarrickCoreUserMemory<'a, A>
where
    ServiceError: From<A::Error>,
{
    fn read_bytes(&mut self, va: GuestVa, buf: &mut [u8]) -> Result<(), NtStatus> {
        if buf.is_empty() {
            return Ok(());
        }
        let range = UserRange::checked(UserVa::new(va.as_u64()), GuestLen::new(buf.len() as u64))
            .ok_or(NtStatus::STATUS_ACCESS_VIOLATION)?;
        self.copy_in(range, buf)
            .map_err(service_error_to_ntstatus)?;
        Ok(())
    }

    fn write_bytes(&mut self, va: GuestVa, buf: &[u8]) -> Result<(), NtStatus> {
        if buf.is_empty() {
            return Ok(());
        }
        let range = UserRange::checked(UserVa::new(va.as_u64()), GuestLen::new(buf.len() as u64))
            .ok_or(NtStatus::STATUS_ACCESS_VIOLATION)?;
        self.copy_out(range, buf)
            .map_err(service_error_to_ntstatus)?;
        Ok(())
    }
}
