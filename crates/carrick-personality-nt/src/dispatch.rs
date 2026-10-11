//! Clean-room NT system call dispatch and control flow lowering.
//!
//! Citations:
//! - docs/design/ntdll-bootstrap.md Section 2.3 & 4.2
//! - Microsoft Learn: WDK Native APIs (NtWriteFile, NtTerminateProcess, NtClose)
//! - Clean-Room Rules: No Wine/ReactOS, no leaked Microsoft code.

use alloc::vec;
use alloc::vec::Vec;
use carrick_nt_abi::{GuestPtr, GuestVa, IoStatusBlock, NtHandle, NtStatus, UserLength};

use crate::call::NtCall;
use crate::handle_table::{HandleObject, HandleTable};
use crate::memory::UserMemory;

/// Execution control flow returned by NT system call dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlFlow<R> {
    /// Return to user mode with the given status code.
    Return(R),
    /// Terminate process execution with the given signed exit status code.
    Terminate(i32),
}

/// Output stream sink interface for console output.
pub trait OutputSink {
    /// Writes output bytes and returns the number of bytes written.
    fn write_output(&mut self, buf: &[u8]) -> Result<usize, NtStatus>;
}

/// In-memory buffer sink for deterministic test execution and receipt verification.
#[derive(Clone, Debug, Default)]
pub struct BufferOutputSink {
    data: Vec<u8>,
}

impl BufferOutputSink {
    /// Creates a new empty buffer sink.
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Returns a slice of the captured output bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Consumes the sink and returns the captured output vector.
    pub fn into_inner(self) -> Vec<u8> {
        self.data
    }
}

impl OutputSink for BufferOutputSink {
    fn write_output(&mut self, buf: &[u8]) -> Result<usize, NtStatus> {
        self.data.extend_from_slice(buf);
        Ok(buf.len())
    }
}

#[cfg(feature = "std")]
/// Standard host stdout sink.
#[derive(Clone, Copy, Debug, Default)]
pub struct StdOutputSink;

#[cfg(feature = "std")]
impl OutputSink for StdOutputSink {
    fn write_output(&mut self, buf: &[u8]) -> Result<usize, NtStatus> {
        use std::io::Write;
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(buf)
            .map_err(|_| NtStatus::STATUS_UNSUCCESSFUL)?;
        let _ = stdout.flush();
        Ok(buf.len())
    }
}

/// Dispatches decoded NT system calls against Carrick services and resources.
pub struct NtDispatcher<M: UserMemory, S: OutputSink> {
    handle_table: HandleTable,
    memory: M,
    sink: S,
}

impl<M: UserMemory, S: OutputSink> NtDispatcher<M, S> {
    /// Creates a new dispatcher with the given handle table, memory provider, and output sink.
    pub fn new(handle_table: HandleTable, memory: M, sink: S) -> Self {
        Self {
            handle_table,
            memory,
            sink,
        }
    }

    /// Accesses the handle table.
    pub fn handle_table(&self) -> &HandleTable {
        &self.handle_table
    }

    /// Mutably accesses the handle table.
    pub fn handle_table_mut(&mut self) -> &mut HandleTable {
        &mut self.handle_table
    }

    /// Accesses the guest memory provider.
    pub fn memory(&self) -> &M {
        &self.memory
    }

    /// Mutably accesses the guest memory provider.
    pub fn memory_mut(&mut self) -> &mut M {
        &mut self.memory
    }

    /// Accesses the output sink.
    pub fn sink(&self) -> &S {
        &self.sink
    }

    /// Mutably accesses the output sink.
    pub fn sink_mut(&mut self) -> &mut S {
        &mut self.sink
    }

    /// Dispatches a typed NT system call, returning the resulting `ControlFlow`.
    pub fn dispatch(&mut self, call: &NtCall) -> ControlFlow<NtStatus> {
        match *call {
            NtCall::TerminateProcess {
                process_handle,
                exit_status,
            } => self.dispatch_terminate_process(process_handle, exit_status),

            NtCall::WriteFile {
                file_handle,
                event: _,
                apc_routine: _,
                apc_context: _,
                io_status_block,
                buffer,
                length,
                byte_offset: _,
                key: _,
            } => self.dispatch_write_file(file_handle, io_status_block, buffer, length),

            NtCall::Close { handle } => self.dispatch_close(handle),
        }
    }

    fn dispatch_terminate_process(
        &mut self,
        process_handle: NtHandle,
        exit_status: NtStatus,
    ) -> ControlFlow<NtStatus> {
        if process_handle.is_null() {
            return ControlFlow::Return(NtStatus::STATUS_INVALID_HANDLE);
        }

        // Current process pseudo-handle is always allowed
        if process_handle == NtHandle::CURRENT_PROCESS {
            return ControlFlow::Terminate(exit_status.as_i32());
        }

        match self.handle_table.lookup(process_handle) {
            Ok(entry) => {
                if let HandleObject::Process { .. } = entry.object {
                    if entry.can_terminate() {
                        ControlFlow::Terminate(exit_status.as_i32())
                    } else {
                        ControlFlow::Return(NtStatus::STATUS_ACCESS_DENIED)
                    }
                } else {
                    ControlFlow::Return(NtStatus::STATUS_OBJECT_TYPE_MISMATCH)
                }
            }
            Err(status) => ControlFlow::Return(status),
        }
    }

    fn dispatch_write_file(
        &mut self,
        file_handle: NtHandle,
        io_status_block: GuestPtr<IoStatusBlock>,
        buffer: GuestVa,
        length: UserLength,
    ) -> ControlFlow<NtStatus> {
        // Validate IO_STATUS_BLOCK pointer
        if io_status_block.is_null() {
            return ControlFlow::Return(NtStatus::STATUS_ACCESS_VIOLATION);
        }

        let entry = match self.handle_table.lookup(file_handle) {
            Ok(e) => e,
            Err(status) => {
                let _ = self.write_io_status(io_status_block, status, 0);
                return ControlFlow::Return(status);
            }
        };

        if !entry.can_write() {
            let _ = self.write_io_status(io_status_block, NtStatus::STATUS_ACCESS_DENIED, 0);
            return ControlFlow::Return(NtStatus::STATUS_ACCESS_DENIED);
        }

        match entry.object {
            HandleObject::ConsoleOutput | HandleObject::ConsoleError => {
                let len = length.as_usize();
                if len == 0 {
                    let _ = self.write_io_status(io_status_block, NtStatus::STATUS_SUCCESS, 0);
                    return ControlFlow::Return(NtStatus::STATUS_SUCCESS);
                }

                if buffer.is_null() {
                    let _ =
                        self.write_io_status(io_status_block, NtStatus::STATUS_ACCESS_VIOLATION, 0);
                    return ControlFlow::Return(NtStatus::STATUS_ACCESS_VIOLATION);
                }

                let mut read_buf = vec![0u8; len];
                if let Err(err) = self.memory.read_bytes(buffer, &mut read_buf) {
                    let _ = self.write_io_status(io_status_block, err, 0);
                    return ControlFlow::Return(err);
                }

                let written = match self.sink.write_output(&read_buf) {
                    Ok(n) => n,
                    Err(err) => {
                        let _ = self.write_io_status(io_status_block, err, 0);
                        return ControlFlow::Return(err);
                    }
                };

                let _ =
                    self.write_io_status(io_status_block, NtStatus::STATUS_SUCCESS, written as u64);
                ControlFlow::Return(NtStatus::STATUS_SUCCESS)
            }
            _ => {
                let _ = self.write_io_status(io_status_block, NtStatus::STATUS_INVALID_HANDLE, 0);
                ControlFlow::Return(NtStatus::STATUS_INVALID_HANDLE)
            }
        }
    }

    fn dispatch_close(&mut self, handle: NtHandle) -> ControlFlow<NtStatus> {
        match self.handle_table.close(handle) {
            Ok(()) => ControlFlow::Return(NtStatus::STATUS_SUCCESS),
            Err(status) => ControlFlow::Return(status),
        }
    }

    fn write_io_status(
        &mut self,
        ptr: GuestPtr<IoStatusBlock>,
        status: NtStatus,
        information: u64,
    ) -> Result<(), NtStatus> {
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&status.as_u32().to_le_bytes());
        bytes[4..8].copy_from_slice(&0u32.to_le_bytes()); // padding
        bytes[8..16].copy_from_slice(&information.to_le_bytes());
        self.memory.write_bytes(ptr.va(), &bytes)
    }
}

/// Encodes an `NtStatus` return value into the x86_64 return register (`rax`).
pub fn encode_return(status: NtStatus, rax: &mut u64) {
    *rax = status.as_u32() as u64;
}
