//! Clean-room guest user-memory abstractions and simulated memory for testing.
//!
//! Citations:
//! - docs/design/ntdll-bootstrap.md Section 2.3 & 3.3
//! - Clean-Room Rules: No Wine/ReactOS, no leaked Microsoft code.

#[cfg(any(test, feature = "test-support"))]
use alloc::collections::BTreeMap;
#[cfg(any(test, feature = "test-support"))]
use carrick_nt_abi::{GuestPtr, IoStatusBlock};
use carrick_nt_abi::{GuestVa, NtStatus};

/// Trait abstracting reading and writing guest virtual memory.
pub trait UserMemory {
    /// Reads a slice of bytes from guest virtual address `va`.
    fn read_bytes(&mut self, va: GuestVa, buf: &mut [u8]) -> Result<(), NtStatus>;

    /// Writes a slice of bytes to guest virtual address `va`.
    fn write_bytes(&mut self, va: GuestVa, buf: &[u8]) -> Result<(), NtStatus>;
}

impl<M: UserMemory + ?Sized> UserMemory for &mut M {
    fn read_bytes(&mut self, va: GuestVa, buf: &mut [u8]) -> Result<(), NtStatus> {
        (**self).read_bytes(va, buf)
    }

    fn write_bytes(&mut self, va: GuestVa, buf: &[u8]) -> Result<(), NtStatus> {
        (**self).write_bytes(va, buf)
    }
}

/// In-memory simulated guest address space for VM-free unit and scenario tests.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug, Default)]
pub struct SimulatedUserMemory {
    pages: BTreeMap<
        u64,
        (
            bool, /* readable */
            bool, /* writable */
            [u8; 4096],
        ),
    >,
}

#[cfg(any(test, feature = "test-support"))]
impl SimulatedUserMemory {
    /// Creates a new empty simulated memory space.
    pub fn new() -> Self {
        Self {
            pages: BTreeMap::new(),
        }
    }

    /// Maps a 4096-byte page with explicit read and write permissions.
    pub fn map_page(&mut self, va: u64, readable: bool, writable: bool) {
        let page_base = va & !0xfff;
        self.pages
            .entry(page_base)
            .and_modify(|entry| {
                entry.0 = readable;
                entry.1 = writable;
            })
            .or_insert((readable, writable, [0u8; 4096]));
    }

    /// Writes data directly into simulated memory, allocating readable/writable pages as needed.
    pub fn write_memory(&mut self, va: u64, data: &[u8]) {
        for (i, &b) in data.iter().enumerate() {
            let addr = va.wrapping_add(i as u64);
            let page_base = addr & !0xfff;
            let offset = (addr & 0xfff) as usize;
            let entry = self
                .pages
                .entry(page_base)
                .or_insert((true, true, [0u8; 4096]));
            entry.2[offset] = b;
        }
    }

    /// Reads an `IoStatusBlock` from guest virtual memory.
    pub fn read_io_status_block(
        &mut self,
        ptr: GuestPtr<IoStatusBlock>,
    ) -> Result<IoStatusBlock, NtStatus> {
        let mut bytes = [0u8; 16];
        self.read_bytes(ptr.va(), &mut bytes)?;
        let status = NtStatus::from_raw(u32::from_le_bytes(
            bytes[0..4]
                .try_into()
                .map_err(|_| NtStatus::STATUS_INVALID_PARAMETER)?,
        ));
        let padding = u32::from_le_bytes(
            bytes[4..8]
                .try_into()
                .map_err(|_| NtStatus::STATUS_INVALID_PARAMETER)?,
        );
        let information = u64::from_le_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| NtStatus::STATUS_INVALID_PARAMETER)?,
        );
        Ok(IoStatusBlock {
            status,
            _padding: padding,
            information,
        })
    }

    /// Writes an `IoStatusBlock` into guest virtual memory.
    pub fn write_io_status_block(
        &mut self,
        ptr: GuestPtr<IoStatusBlock>,
        iosb: &IoStatusBlock,
    ) -> Result<(), NtStatus> {
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&iosb.status.as_u32().to_le_bytes());
        bytes[4..8].copy_from_slice(&iosb._padding.to_le_bytes());
        bytes[8..16].copy_from_slice(&iosb.information.to_le_bytes());
        self.write_bytes(ptr.va(), &bytes)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl UserMemory for SimulatedUserMemory {
    fn read_bytes(&mut self, va: GuestVa, buf: &mut [u8]) -> Result<(), NtStatus> {
        if buf.is_empty() {
            return Ok(());
        }
        let start = va.as_u64();
        for (i, byte) in buf.iter_mut().enumerate() {
            let addr = start
                .checked_add(i as u64)
                .ok_or(NtStatus::STATUS_ACCESS_VIOLATION)?;
            let page_base = addr & !0xfff;
            let offset = (addr & 0xfff) as usize;
            let (readable, _, data) = self
                .pages
                .get(&page_base)
                .ok_or(NtStatus::STATUS_ACCESS_VIOLATION)?;
            if !readable {
                return Err(NtStatus::STATUS_ACCESS_VIOLATION);
            }
            *byte = data[offset];
        }
        Ok(())
    }

    fn write_bytes(&mut self, va: GuestVa, buf: &[u8]) -> Result<(), NtStatus> {
        if buf.is_empty() {
            return Ok(());
        }
        let start = va.as_u64();
        // First pass: verify permissions across entire span
        for i in 0..buf.len() {
            let addr = start
                .checked_add(i as u64)
                .ok_or(NtStatus::STATUS_ACCESS_VIOLATION)?;
            let page_base = addr & !0xfff;
            let (_, writable, _) = self
                .pages
                .get(&page_base)
                .ok_or(NtStatus::STATUS_ACCESS_VIOLATION)?;
            if !writable {
                return Err(NtStatus::STATUS_ACCESS_VIOLATION);
            }
        }
        // Second pass: perform writes
        for (i, &b) in buf.iter().enumerate() {
            let addr = start + i as u64;
            let page_base = addr & !0xfff;
            let offset = (addr & 0xfff) as usize;
            if let Some((_, _, data)) = self.pages.get_mut(&page_base) {
                data[offset] = b;
            }
        }
        Ok(())
    }
}
