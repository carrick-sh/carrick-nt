//! Clean-room Windows NT object handle table and lifecycle management.
//!
//! Citations:
//! - docs/design/ntdll-bootstrap.md Section 2.3 & 3.8: Standard Handles & Console Initialization
//! - Microsoft Learn: Handles and Objects
//!   https://learn.microsoft.com/en-us/windows/win32/sysinfo/handles-and-objects
//! - Microsoft Learn: Standard Access Rights
//!   https://learn.microsoft.com/en-us/windows/win32/secauthz/standard-access-rights
//! - Clean-Room Rules: No Wine/ReactOS, no leaked Microsoft code.

use alloc::collections::BTreeMap;
use alloc::string::String;
use carrick_nt_abi::{NtHandle, NtStatus};

/// Standard NT access rights and object permissions.
pub mod access_rights {
    pub const FILE_READ_DATA: u32 = 0x0001;
    pub const FILE_WRITE_DATA: u32 = 0x0002;
    pub const FILE_APPEND_DATA: u32 = 0x0004;
    pub const PROCESS_TERMINATE: u32 = 0x0001;
    pub const PROCESS_ALL_ACCESS: u32 = 0x001F_0FFF;
    pub const THREAD_ALL_ACCESS: u32 = 0x001F_03FF;
    pub const GENERIC_READ: u32 = 0x8000_0000;
    pub const GENERIC_WRITE: u32 = 0x4000_0000;
    pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
    pub const GENERIC_ALL: u32 = 0x1000_0000;
}

/// The underlying object referenced by an NT handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandleObject {
    /// Standard console output stream (stdout).
    ConsoleOutput,
    /// Standard console input stream (stdin).
    ConsoleInput,
    /// Standard console error stream (stderr).
    ConsoleError,
    /// Process object.
    Process { pid: u64 },
    /// Thread object.
    Thread { tid: u64 },
    /// File or device object.
    File { path: String },
}

/// An entry in the NT object handle table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandleEntry {
    /// The object referenced by this handle.
    pub object: HandleObject,
    /// Granted access mask for this handle.
    pub access_rights: u32,
    /// Whether child processes inherit this handle.
    pub inherit: bool,
}

impl HandleEntry {
    /// Creates a new `HandleEntry` with the given object and access rights.
    pub const fn new(object: HandleObject, access_rights: u32) -> Self {
        Self {
            object,
            access_rights,
            inherit: false,
        }
    }

    /// Checks if the entry has write access granted.
    pub const fn can_write(&self) -> bool {
        (self.access_rights & (access_rights::GENERIC_WRITE | access_rights::FILE_WRITE_DATA)) != 0
    }

    /// Checks if the entry has read access granted.
    pub const fn can_read(&self) -> bool {
        (self.access_rights & (access_rights::GENERIC_READ | access_rights::FILE_READ_DATA)) != 0
    }

    /// Checks if the entry has process termination rights.
    pub const fn can_terminate(&self) -> bool {
        (self.access_rights
            & (access_rights::PROCESS_TERMINATE | access_rights::PROCESS_ALL_ACCESS))
            != 0
    }
}

/// Process-level NT handle table.
#[derive(Clone, Debug)]
pub struct HandleTable {
    entries: BTreeMap<u64, HandleEntry>,
    next_handle: u64,
    process_id: u64,
    thread_id: u64,
}

impl HandleTable {
    /// Creates a new empty handle table with the given PID and TID.
    pub fn new(process_id: u64, thread_id: u64) -> Self {
        Self {
            entries: BTreeMap::new(),
            next_handle: 4, // Windows handles start at 4 and increment in multiples of 4
            process_id,
            thread_id,
        }
    }

    /// Creates a handle table initialized with standard console handles.
    pub fn with_standard_handles(process_id: u64, thread_id: u64) -> Self {
        let mut table = Self::new(process_id, thread_id);
        // Pre-insert standard handles at traditional indices (0x4, 0x8, 0xC)
        let _ = table.insert_at(
            NtHandle::from_raw(4),
            HandleObject::ConsoleInput,
            access_rights::GENERIC_READ | access_rights::FILE_READ_DATA,
        );
        let _ = table.insert_at(
            NtHandle::from_raw(8),
            HandleObject::ConsoleOutput,
            access_rights::GENERIC_WRITE | access_rights::FILE_WRITE_DATA,
        );
        let _ = table.insert_at(
            NtHandle::from_raw(12),
            HandleObject::ConsoleError,
            access_rights::GENERIC_WRITE | access_rights::FILE_WRITE_DATA,
        );
        table.next_handle = 16;
        table
    }

    /// Allocates the next sequential handle and registers the given object.
    pub fn allocate(
        &mut self,
        object: HandleObject,
        access_rights: u32,
    ) -> Result<NtHandle, NtStatus> {
        let handle_val = self.next_handle;
        self.next_handle = self
            .next_handle
            .checked_add(4)
            .ok_or(NtStatus::STATUS_UNSUCCESSFUL)?;

        let handle = NtHandle::from_raw(handle_val);
        self.entries
            .insert(handle_val, HandleEntry::new(object, access_rights));
        Ok(handle)
    }

    /// Inserts an object at a specific explicit handle value.
    pub fn insert_at(
        &mut self,
        handle: NtHandle,
        object: HandleObject,
        access_rights: u32,
    ) -> Result<(), NtStatus> {
        if handle.is_invalid() || handle.is_pseudo() {
            return Err(NtStatus::STATUS_INVALID_PARAMETER);
        }
        self.entries
            .insert(handle.as_u64(), HandleEntry::new(object, access_rights));
        Ok(())
    }

    /// Looks up a handle in the table, resolving pseudo-handles transparently.
    pub fn lookup(&self, handle: NtHandle) -> Result<HandleEntry, NtStatus> {
        if handle.is_null() {
            return Err(NtStatus::STATUS_INVALID_HANDLE);
        }

        // 1. Resolve standard pseudo-handles
        if handle == NtHandle::STD_OUTPUT {
            return Ok(HandleEntry::new(
                HandleObject::ConsoleOutput,
                access_rights::GENERIC_WRITE | access_rights::FILE_WRITE_DATA,
            ));
        }
        if handle == NtHandle::STD_INPUT {
            return Ok(HandleEntry::new(
                HandleObject::ConsoleInput,
                access_rights::GENERIC_READ | access_rights::FILE_READ_DATA,
            ));
        }
        if handle == NtHandle::STD_ERROR {
            return Ok(HandleEntry::new(
                HandleObject::ConsoleError,
                access_rights::GENERIC_WRITE | access_rights::FILE_WRITE_DATA,
            ));
        }
        if handle == NtHandle::CURRENT_PROCESS {
            return Ok(HandleEntry::new(
                HandleObject::Process {
                    pid: self.process_id,
                },
                access_rights::PROCESS_ALL_ACCESS,
            ));
        }
        if handle == NtHandle::CURRENT_THREAD {
            return Ok(HandleEntry::new(
                HandleObject::Thread {
                    tid: self.thread_id,
                },
                access_rights::THREAD_ALL_ACCESS,
            ));
        }

        // Other pseudo-handles not recognized are invalid
        if handle.is_pseudo() {
            return Err(NtStatus::STATUS_INVALID_HANDLE);
        }

        // 2. Look up in table entries
        self.entries
            .get(&handle.as_u64())
            .cloned()
            .ok_or(NtStatus::STATUS_INVALID_HANDLE)
    }

    /// Closes an open object handle.
    ///
    /// Pseudo-handles cannot be closed; attempting to close one returns `STATUS_INVALID_HANDLE`.
    pub fn close(&mut self, handle: NtHandle) -> Result<(), NtStatus> {
        if handle.is_null() || handle.is_pseudo() {
            return Err(NtStatus::STATUS_INVALID_HANDLE);
        }

        if self.entries.remove(&handle.as_u64()).is_some() {
            Ok(())
        } else {
            Err(NtStatus::STATUS_INVALID_HANDLE)
        }
    }

    /// Returns the number of entries in the handle table.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the handle table has no registered entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the process ID associated with this handle table.
    pub fn process_id(&self) -> u64 {
        self.process_id
    }

    /// Returns the thread ID associated with this handle table.
    pub fn thread_id(&self) -> u64 {
        self.thread_id
    }
}
