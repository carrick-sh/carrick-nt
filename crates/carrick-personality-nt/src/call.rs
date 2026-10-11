//! Clean-room Windows NT system call representation and decoding.
//!
//! Citations:
//! - docs/design/ntdll-bootstrap.md Section 2.3: "The Carrick NT Hypercall / System Call Contract"
//! - Microsoft Learn: WDK Native APIs (NtWriteFile, NtTerminateProcess, NtClose)
//! - Clean-Room Rules: No Wine/ReactOS, no leaked Microsoft code.

use carrick_core::personality::CallOrdinal;
use carrick_nt_abi::{
    GuestPtr, GuestVa, IoStatusBlock, NtHandle, NtServiceId, NtStatus, UserLength,
};

/// Typed Windows NT system call representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NtCall {
    /// Terminates the specified process and all its threads.
    ///
    /// Parameters:
    /// - `process_handle`: Handle to the process to be terminated (or `CURRENT_PROCESS`).
    /// - `exit_status`: The exit status code.
    TerminateProcess {
        process_handle: NtHandle,
        exit_status: NtStatus,
    },

    /// Writes data to an open file or device stream.
    ///
    /// Parameters:
    /// - `file_handle`: Handle to the file or device object.
    /// - `event`: Optional event object to be signaled upon completion.
    /// - `apc_routine`: Optional APC routine to be executed upon completion.
    /// - `apc_context`: Optional argument for the APC routine.
    /// - `io_status_block`: Pointer to receive the completion status and byte count.
    /// - `buffer`: Pointer to the buffer containing data to be written.
    /// - `length`: Length of the buffer in bytes.
    /// - `byte_offset`: Optional file offset where writing begins.
    /// - `key`: Optional caller key.
    WriteFile {
        file_handle: NtHandle,
        event: NtHandle,
        apc_routine: GuestVa,
        apc_context: GuestVa,
        io_status_block: GuestPtr<IoStatusBlock>,
        buffer: GuestVa,
        length: UserLength,
        byte_offset: GuestVa,
        key: GuestVa,
    },

    /// Closes an open object handle.
    ///
    /// Parameters:
    /// - `handle`: Handle to be closed.
    Close { handle: NtHandle },
}

impl NtCall {
    /// Returns the typed `CallOrdinal` associated with this system call.
    pub fn ordinal(&self) -> CallOrdinal {
        match self {
            Self::TerminateProcess { .. } => {
                CallOrdinal::from_raw(NtServiceId::NtTerminateProcess.as_u32() as u64)
            }
            Self::Close { .. } => CallOrdinal::from_raw(NtServiceId::NtClose.as_u32() as u64),
            Self::WriteFile { .. } => {
                CallOrdinal::from_raw(NtServiceId::NtWriteFile.as_u32() as u64)
            }
        }
    }
}
