//! Clean-room Windows NT system call representation and decoding.
//!
//! Citations:
//! - docs/design/ntdll-bootstrap.md Section 2.3: "The Carrick NT Hypercall / System Call Contract"
//! - Microsoft Learn: WDK Native APIs (NtWriteFile, NtTerminateProcess, NtClose)
//! - Clean-Room Rules: No Wine/ReactOS, no leaked Microsoft code.

use carrick_core::personality::DecodedCall;
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

impl TryFrom<&DecodedCall> for NtCall {
    type Error = NtStatus;

    fn try_from(call: &DecodedCall) -> Result<Self, Self::Error> {
        let service = match NtServiceId::from_u32(call.ordinal as u32) {
            Some(s) => s,
            None => return Err(NtStatus::STATUS_NOT_IMPLEMENTED),
        };

        match service {
            NtServiceId::NtTerminateProcess => {
                if call.arity.get() < 2 {
                    return Err(NtStatus::STATUS_INVALID_PARAMETER);
                }
                Ok(Self::TerminateProcess {
                    process_handle: NtHandle::from_raw(call.args[0]),
                    exit_status: NtStatus::from_raw(call.args[1] as u32),
                })
            }
            NtServiceId::NtClose => {
                if call.arity.get() < 1 {
                    return Err(NtStatus::STATUS_INVALID_PARAMETER);
                }
                Ok(Self::Close {
                    handle: NtHandle::from_raw(call.args[0]),
                })
            }
            NtServiceId::NtWriteFile => {
                if call.arity.get() < 9 {
                    return Err(NtStatus::STATUS_INVALID_PARAMETER);
                }
                Ok(Self::WriteFile {
                    file_handle: NtHandle::from_raw(call.args[0]),
                    event: NtHandle::from_raw(call.args[1]),
                    apc_routine: GuestVa::new(call.args[2]),
                    apc_context: GuestVa::new(call.args[3]),
                    io_status_block: GuestPtr::from_raw(call.args[4]),
                    buffer: GuestVa::new(call.args[5]),
                    length: UserLength::new(call.args[6] as u32),
                    byte_offset: GuestVa::new(call.args[7]),
                    key: GuestVa::new(call.args[8]),
                })
            }
        }
    }
}
