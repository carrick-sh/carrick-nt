//! Integration and unit tests for carrick-personality-nt.
//!
//! Witness verification:
//! - Unit tests for the decode convention (the NT x64 syscall ABI register/stack spill).
//! - NTSTATUS mapping and severity bit semantics.
//! - Handle table lifecycle and pseudo-handle semantics.
//! - Simulated CallContext integration executing NtWriteFile and NtTerminateProcess.
//! - Differential conformance check against committed oracle receipt hello_console.json.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::HashMap;

use carrick_core::personality::{CallContext, EntryDecodeError, UserStackOffset};
use carrick_core::Personality;
use carrick_guest_arch::{
    Arch, ArchTypes, EntryBackend, EntryEvent, KernelStackPointer, NativeEntrySnapshot,
    NativeReturnWord, ThreadPointerRegister, UserReturn, UserVa,
};
use carrick_nt_abi::{GuestPtr, GuestVa, NtHandle, NtServiceId, NtStatus, UserLength};
use carrick_personality_nt::handle_table::access_rights;
use carrick_personality_nt::{
    encode_return, BufferOutputSink, ControlFlow, HandleObject, HandleTable, NtCall, NtDispatcher,
    NtPersonality, SimulatedUserMemory, NT_X64_STACK_ARG_BASE_OFFSET,
};

// ============================================================================
// Simulated Entry Frame & Backend for CallContext Testing
// ============================================================================

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TestFrame {
    ordinal: u64,
    /// Arguments: [0: rdi, 1: rsi, 2: rdx, 3: r10, 4: r8, 5: r9]
    reg_args: [u64; 6],
    user_sp: UserVa,
    rax: u64,
}

#[derive(Debug, Default)]
struct TestEntryBackend {
    pages: HashMap<u64, (bool /* readable */, [u8; 4096])>,
}

impl TestEntryBackend {
    fn new() -> Self {
        Self {
            pages: HashMap::new(),
        }
    }

    fn map_page(&mut self, va: u64, readable: bool) {
        let page_base = va & !0xfff;
        self.pages
            .entry(page_base)
            .or_insert((readable, [0u8; 4096]))
            .0 = readable;
    }

    fn write_u64(&mut self, va: u64, val: u64) {
        let page_base = va & !0xfff;
        let offset = (va & 0xfff) as usize;
        let entry = self.pages.entry(page_base).or_insert((true, [0u8; 4096]));
        if offset + 8 <= 4096 {
            entry.1[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
        }
    }

    fn create_frame(&self, service: NtServiceId, reg_args: [u64; 6], user_sp: u64) -> TestFrame {
        TestFrame {
            ordinal: service.as_u32() as u64,
            reg_args,
            user_sp: UserVa::new(user_sp),
            rax: service.as_u32() as u64,
        }
    }
}

impl ArchTypes for TestEntryBackend {
    type Error = EntryDecodeError;
    type NativeFrame = TestFrame;
    type SavedContext = ();
    type Context = [u64; 4];
    type Root = u64;
    type MmOwner = ();
    type DrainTicket = ();
    type DrainReceipt = ();
    type UserTransfer = ();
    type HardwareInterrupt = u32;
    type InterruptMask = u32;
}

impl EntryBackend for TestEntryBackend {
    fn current_stack_pointer(&mut self) -> Result<KernelStackPointer, Self::Error> {
        Ok(KernelStackPointer::new(0x7000_0000))
    }

    fn decode_entry(&mut self, _frame: &Self::NativeFrame) -> Result<EntryEvent, Self::Error> {
        Err(EntryDecodeError::InvalidFrame)
    }

    fn snapshot<'a>(
        &mut self,
        _frame: &'a Self::NativeFrame,
    ) -> Result<NativeEntrySnapshot<'a, Self::NativeFrame>, Self::Error> {
        Err(EntryDecodeError::InvalidFrame)
    }

    fn set_result(
        &mut self,
        frame: &mut Self::NativeFrame,
        result: NativeReturnWord,
    ) -> Result<(), Self::Error> {
        frame.rax = result.0;
        Ok(())
    }

    fn save_context(
        &mut self,
        _frame: &Self::NativeFrame,
    ) -> Result<Self::SavedContext, Self::Error> {
        Ok(())
    }

    fn load_context(
        &mut self,
        _frame: &mut Self::NativeFrame,
        _saved: &Self::SavedContext,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn prepare_user_return(
        &mut self,
        _frame: &Self::NativeFrame,
    ) -> Result<UserReturn, Self::Error> {
        Err(EntryDecodeError::InvalidFrame)
    }

    fn user_stack_pointer(&mut self, frame: &Self::NativeFrame) -> Result<UserVa, Self::Error> {
        Ok(frame.user_sp)
    }

    fn register_argument(
        &mut self,
        frame: &Self::NativeFrame,
        index: usize,
    ) -> Result<u64, Self::Error> {
        if index < frame.reg_args.len() {
            Ok(frame.reg_args[index])
        } else {
            Err(EntryDecodeError::OutOfBounds)
        }
    }

    fn syscall_ordinal(&mut self, frame: &Self::NativeFrame) -> Result<u64, Self::Error> {
        Ok(frame.ordinal)
    }

    fn read_user_stack(
        &mut self,
        frame: &Self::NativeFrame,
        offset: UserStackOffset,
    ) -> Result<u64, Self::Error> {
        let va = frame
            .user_sp
            .raw()
            .checked_add(offset.raw())
            .ok_or(EntryDecodeError::Fault)?;
        let page_base = va & !0xfff;
        let page_offset = (va & 0xfff) as usize;
        let (readable, data) = self.pages.get(&page_base).ok_or(EntryDecodeError::Fault)?;
        if !readable {
            return Err(EntryDecodeError::Fault);
        }
        if page_offset + 8 > 4096 {
            return Err(EntryDecodeError::Fault);
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&data[page_offset..page_offset + 8]);
        Ok(u64::from_le_bytes(bytes))
    }

    fn copy_user_stack(
        &mut self,
        _frame: &Self::NativeFrame,
        _offset: UserStackOffset,
        _out: &mut [u8],
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

// ============================================================================
// 1. Syscall Decode Convention Tests
// ============================================================================

#[test]
fn test_decode_nt_terminate_process() {
    let personality = NtPersonality::new();
    let backend = TestEntryBackend::new();

    // Register arguments: index 3 = r10 (arg1: process_handle), index 2 = rdx (arg2: exit_status)
    let mut reg_args = [0u64; 6];
    reg_args[3] = NtHandle::CURRENT_PROCESS.as_u64();
    reg_args[2] = 42; // exit status

    let frame = backend.create_frame(NtServiceId::NtTerminateProcess, reg_args, 0x0000_7FFF_0000);
    let mut arch = Arch::new(backend);
    let mut cx = CallContext::new(&mut arch, &frame);

    let decoded = personality
        .decode(&mut cx)
        .expect("NtTerminateProcess decode must succeed");

    assert_eq!(
        decoded.ordinal,
        NtServiceId::NtTerminateProcess.as_u32() as u64
    );
    assert_eq!(decoded.arity.get(), 2);
    assert_eq!(decoded.args[0], NtHandle::CURRENT_PROCESS.as_u64());
    assert_eq!(decoded.args[1], 42);

    let nt_call = NtCall::try_from(&decoded).expect("NtCall conversion must succeed");
    match nt_call {
        NtCall::TerminateProcess {
            process_handle,
            exit_status,
        } => {
            assert_eq!(process_handle, NtHandle::CURRENT_PROCESS);
            assert_eq!(exit_status, NtStatus::from_raw(42));
        }
        _ => panic!("Expected NtCall::TerminateProcess"),
    }
}

#[test]
fn test_decode_nt_close() {
    let personality = NtPersonality::new();
    let backend = TestEntryBackend::new();

    let mut reg_args = [0u64; 6];
    reg_args[3] = 0x24; // Handle 0x24 in r10 (index 3)

    let frame = backend.create_frame(NtServiceId::NtClose, reg_args, 0x0000_7FFF_0000);
    let mut arch = Arch::new(backend);
    let mut cx = CallContext::new(&mut arch, &frame);

    let decoded = personality
        .decode(&mut cx)
        .expect("NtClose decode must succeed");
    assert_eq!(decoded.ordinal, NtServiceId::NtClose.as_u32() as u64);
    assert_eq!(decoded.arity.get(), 1);
    assert_eq!(decoded.args[0], 0x24);

    let nt_call = NtCall::try_from(&decoded).expect("NtCall conversion must succeed");
    assert_eq!(
        nt_call,
        NtCall::Close {
            handle: NtHandle::from_raw(0x24)
        }
    );
}

#[test]
fn test_decode_nt_write_file_register_and_stack_spill() {
    let personality = NtPersonality::new();
    let mut backend = TestEntryBackend::new();

    let stack_va = 0x0000_7FFF_1000u64;
    backend.map_page(stack_va, true /* readable */);

    // Write spilled arguments onto user stack starting at offset 0x28
    let iosb_va = 0x0000_7FFF_2000u64;
    let buf_va = 0x0000_7FFF_3000u64;
    backend.write_u64(stack_va + NT_X64_STACK_ARG_BASE_OFFSET, iosb_va); // Arg 5 (offset 0x28)
    backend.write_u64(stack_va + NT_X64_STACK_ARG_BASE_OFFSET + 8, buf_va); // Arg 6 (offset 0x30)
    backend.write_u64(stack_va + NT_X64_STACK_ARG_BASE_OFFSET + 16, 20); // Arg 7: length (offset 0x38)
    backend.write_u64(stack_va + NT_X64_STACK_ARG_BASE_OFFSET + 24, 0); // Arg 8: byte_offset (offset 0x40)
    backend.write_u64(stack_va + NT_X64_STACK_ARG_BASE_OFFSET + 32, 0); // Arg 9: key (offset 0x48)

    // Register arguments:
    let mut reg_args = [0u64; 6];
    reg_args[3] = NtHandle::STD_OUTPUT.as_u64(); // Arg 1: file_handle in r10 (index 3)
    reg_args[2] = 0; // Arg 2: event in rdx (index 2)
    reg_args[4] = 0; // Arg 3: apc_routine in r8 (index 4)
    reg_args[5] = 0; // Arg 4: apc_context in r9 (index 5)

    let frame = backend.create_frame(NtServiceId::NtWriteFile, reg_args, stack_va);
    let mut arch = Arch::new(backend);
    let mut cx = CallContext::new(&mut arch, &frame);

    let decoded = personality
        .decode(&mut cx)
        .expect("NtWriteFile decode must succeed");

    assert_eq!(decoded.ordinal, NtServiceId::NtWriteFile.as_u32() as u64);
    assert_eq!(decoded.arity.get(), 9);
    assert_eq!(decoded.args[0], NtHandle::STD_OUTPUT.as_u64());
    assert_eq!(decoded.args[1], 0);
    assert_eq!(decoded.args[2], 0);
    assert_eq!(decoded.args[3], 0);
    assert_eq!(decoded.args[4], iosb_va);
    assert_eq!(decoded.args[5], buf_va);
    assert_eq!(decoded.args[6], 20);
    assert_eq!(decoded.args[7], 0);
    assert_eq!(decoded.args[8], 0);

    let nt_call = NtCall::try_from(&decoded).expect("NtCall conversion must succeed");
    match nt_call {
        NtCall::WriteFile {
            file_handle,
            event,
            apc_routine,
            apc_context,
            io_status_block,
            buffer,
            length,
            byte_offset,
            key,
        } => {
            assert_eq!(file_handle, NtHandle::STD_OUTPUT);
            assert_eq!(event, NtHandle::NULL);
            assert_eq!(apc_routine, GuestVa::NULL);
            assert_eq!(apc_context, GuestVa::NULL);
            assert_eq!(io_status_block, GuestPtr::from_raw(iosb_va));
            assert_eq!(buffer, GuestVa::new(buf_va));
            assert_eq!(length, UserLength::new(20));
            assert_eq!(byte_offset, GuestVa::NULL);
            assert_eq!(key, GuestVa::NULL);
        }
        _ => panic!("Expected NtCall::WriteFile"),
    }
}

#[test]
fn test_decode_unmapped_stack_returns_fault() {
    let personality = NtPersonality::new();
    let backend = TestEntryBackend::new();

    // Stack pointer points to unmapped address
    let unmapped_sp = 0xDEAD_BEEF_0000u64;
    let frame = backend.create_frame(NtServiceId::NtWriteFile, [0; 6], unmapped_sp);
    let mut arch = Arch::new(backend);
    let mut cx = CallContext::new(&mut arch, &frame);

    let err = personality.decode(&mut cx);
    assert_eq!(
        err,
        Err(EntryDecodeError::Fault),
        "Accessing unmapped stack must return EntryDecodeError::Fault"
    );
}

#[test]
fn test_decode_protected_stack_returns_fault() {
    let personality = NtPersonality::new();
    let mut backend = TestEntryBackend::new();

    let stack_va = 0x0000_7FFF_1000u64;
    backend.map_page(stack_va, false /* not readable */);

    let frame = backend.create_frame(NtServiceId::NtWriteFile, [0; 6], stack_va);
    let mut arch = Arch::new(backend);
    let mut cx = CallContext::new(&mut arch, &frame);

    let err = personality.decode(&mut cx);
    assert_eq!(
        err,
        Err(EntryDecodeError::Fault),
        "Accessing unreadable stack must return EntryDecodeError::Fault"
    );
}

#[test]
fn test_decode_unsupported_service_ordinal() {
    let personality = NtPersonality::new();
    let backend = TestEntryBackend::new();

    let mut frame = backend.create_frame(NtServiceId::NtClose, [0; 6], 0x7fff_0000);
    frame.ordinal = 9999; // Invalid service ID

    let mut arch = Arch::new(backend);
    let mut cx = CallContext::new(&mut arch, &frame);

    let err = personality.decode(&mut cx);
    assert_eq!(
        err,
        Err(EntryDecodeError::UnsupportedAbi),
        "Unknown ordinal must return EntryDecodeError::UnsupportedAbi"
    );
}

#[test]
fn test_thread_pointer_register_is_gs() {
    let personality = NtPersonality::new();
    assert_eq!(
        personality.thread_pointer_register(),
        ThreadPointerRegister::GS,
        "Windows NT on x86_64 must use GS as the thread environment pointer"
    );
}

// ============================================================================
// 2. NTSTATUS Mapping Tests
// ============================================================================

#[test]
fn test_ntstatus_mapping_and_severities() {
    // Severity 00b = Success
    assert!(NtStatus::STATUS_SUCCESS.is_success());
    assert!(!NtStatus::STATUS_SUCCESS.is_error());
    assert_eq!(NtStatus::STATUS_SUCCESS.as_u32(), 0x0000_0000);

    // Severity 11b = Error
    assert!(!NtStatus::STATUS_UNSUCCESSFUL.is_success());
    assert!(NtStatus::STATUS_UNSUCCESSFUL.is_error());
    assert_eq!(NtStatus::STATUS_UNSUCCESSFUL.as_u32(), 0xC000_0001);

    assert!(!NtStatus::STATUS_INVALID_HANDLE.is_success());
    assert!(NtStatus::STATUS_INVALID_HANDLE.is_error());
    assert_eq!(NtStatus::STATUS_INVALID_HANDLE.as_u32(), 0xC000_0008);

    assert!(!NtStatus::STATUS_ACCESS_VIOLATION.is_success());
    assert!(NtStatus::STATUS_ACCESS_VIOLATION.is_error());
    assert_eq!(NtStatus::STATUS_ACCESS_VIOLATION.as_u32(), 0xC000_0005);

    assert!(!NtStatus::STATUS_OBJECT_TYPE_MISMATCH.is_success());
    assert!(NtStatus::STATUS_OBJECT_TYPE_MISMATCH.is_error());
    assert_eq!(NtStatus::STATUS_OBJECT_TYPE_MISMATCH.as_u32(), 0xC000_0024);

    // Round-trip signed conversions
    let status = NtStatus::STATUS_UNSUCCESSFUL;
    assert_eq!(status.as_i32(), -1073741823);
    assert_eq!(NtStatus::from_raw(status.as_u32()), status);
}

// ============================================================================
// 3. Handle Table Lifecycle Tests
// ============================================================================

#[test]
fn test_handle_table_lifecycle() {
    let mut table = HandleTable::new(1000, 1001);
    assert!(table.is_empty());
    assert_eq!(table.len(), 0);

    // 1. Allocate dynamic handles (multiples of 4)
    let h1 = table
        .allocate(HandleObject::ConsoleOutput, access_rights::GENERIC_WRITE)
        .expect("allocate must succeed");
    assert_eq!(h1.as_u64(), 4);
    assert_eq!(table.len(), 1);

    let h2 = table
        .allocate(HandleObject::ConsoleInput, access_rights::GENERIC_READ)
        .expect("allocate must succeed");
    assert_eq!(h2.as_u64(), 8);
    assert_eq!(table.len(), 2);

    // 2. Lookup handles
    let entry1 = table.lookup(h1).expect("h1 lookup must succeed");
    assert_eq!(entry1.object, HandleObject::ConsoleOutput);
    assert!(entry1.can_write());
    assert!(!entry1.can_read());

    let entry2 = table.lookup(h2).expect("h2 lookup must succeed");
    assert_eq!(entry2.object, HandleObject::ConsoleInput);
    assert!(entry2.can_read());
    assert!(!entry2.can_write());

    // 3. Lookup invalid and non-existent handles
    assert_eq!(
        table.lookup(NtHandle::NULL),
        Err(NtStatus::STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        table.lookup(NtHandle::from_raw(999)),
        Err(NtStatus::STATUS_INVALID_HANDLE)
    );

    // 4. Resolve pseudo-handles
    let stdout_entry = table
        .lookup(NtHandle::STD_OUTPUT)
        .expect("STD_OUTPUT lookup must succeed");
    assert_eq!(stdout_entry.object, HandleObject::ConsoleOutput);
    assert!(stdout_entry.can_write());

    let cur_proc_entry = table
        .lookup(NtHandle::CURRENT_PROCESS)
        .expect("CURRENT_PROCESS lookup must succeed");
    assert_eq!(cur_proc_entry.object, HandleObject::Process { pid: 1000 });
    assert!(cur_proc_entry.can_terminate());

    let cur_thread_entry = table
        .lookup(NtHandle::CURRENT_THREAD)
        .expect("CURRENT_THREAD lookup must succeed");
    assert_eq!(cur_thread_entry.object, HandleObject::Thread { tid: 1001 });

    // 5. Close handles
    // Closing pseudo-handle must fail
    assert_eq!(
        table.close(NtHandle::CURRENT_PROCESS),
        Err(NtStatus::STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        table.close(NtHandle::STD_OUTPUT),
        Err(NtStatus::STATUS_INVALID_HANDLE)
    );

    // Closing valid table handle succeeds
    assert_eq!(table.close(h1), Ok(()));
    assert_eq!(table.len(), 1);
    assert_eq!(table.lookup(h1), Err(NtStatus::STATUS_INVALID_HANDLE));

    // Double close fails
    assert_eq!(table.close(h1), Err(NtStatus::STATUS_INVALID_HANDLE));
}

// ============================================================================
// 4. Simulated CallContext Integration: NtWriteFile & NtTerminateProcess
// ============================================================================

#[test]
fn test_integration_simulated_callcontext_executes_write_and_terminate() {
    let personality = NtPersonality::new();
    let mut backend = TestEntryBackend::new();

    // Set up guest memory and handle table
    let mut memory = SimulatedUserMemory::new();
    let handle_table = HandleTable::with_standard_handles(1000, 1001);
    let sink = BufferOutputSink::new();

    // Map stdout handle (handle 8 or pseudo handle STD_OUTPUT)
    let stdout_handle = NtHandle::STD_OUTPUT;

    // Prepare message buffer in guest memory: "Hello, Carrick NT!\r\n"
    let message = b"Hello, Carrick NT!\r\n";
    let buffer_va = 0x0000_0001_4000_1000u64;
    memory.write_memory(buffer_va, message);

    // Prepare IO_STATUS_BLOCK in guest memory (16 bytes, uninitialized)
    let iosb_va = 0x0000_0001_4000_2000u64;
    memory.map_page(iosb_va, true /* readable */, true /* writable */);

    // Prepare entry stack with spilled arguments
    let stack_va = 0x0000_0000_7000_8000u64;
    backend.map_page(stack_va, true /* readable */);
    backend.write_u64(stack_va + NT_X64_STACK_ARG_BASE_OFFSET, iosb_va); // Arg 5: io_status_block
    backend.write_u64(stack_va + NT_X64_STACK_ARG_BASE_OFFSET + 8, buffer_va); // Arg 6: buffer
    backend.write_u64(
        stack_va + NT_X64_STACK_ARG_BASE_OFFSET + 16,
        message.len() as u64,
    ); // Arg 7: length
    backend.write_u64(stack_va + NT_X64_STACK_ARG_BASE_OFFSET + 24, 0); // Arg 8: byte_offset
    backend.write_u64(stack_va + NT_X64_STACK_ARG_BASE_OFFSET + 32, 0); // Arg 9: key

    // Register arguments for NtWriteFile
    let mut reg_args = [0u64; 6];
    reg_args[3] = stdout_handle.as_u64(); // r10 = file_handle
    reg_args[2] = 0; // rdx = event
    reg_args[4] = 0; // r8  = apc_routine
    reg_args[5] = 0; // r9  = apc_context

    let frame = backend.create_frame(NtServiceId::NtWriteFile, reg_args, stack_va);
    let mut arch = Arch::new(backend);
    let mut cx = CallContext::new(&mut arch, &frame);

    // 1. Decode NtWriteFile from CallContext
    let decoded = personality
        .decode(&mut cx)
        .expect("NtWriteFile decode must succeed");
    let nt_call = NtCall::try_from(&decoded).expect("NtCall conversion must succeed");

    // 2. Dispatch NtWriteFile
    let mut dispatcher = NtDispatcher::new(handle_table, memory, sink);
    let flow = dispatcher.dispatch(&nt_call);
    assert_eq!(flow, ControlFlow::Return(NtStatus::STATUS_SUCCESS));

    // 3. Verify IO_STATUS_BLOCK updated in guest memory
    let iosb = dispatcher
        .memory()
        .read_io_status_block(GuestPtr::from_raw(iosb_va))
        .expect("read_io_status_block must succeed");
    assert_eq!(iosb.status, NtStatus::STATUS_SUCCESS);
    assert_eq!(iosb.information, message.len() as u64);

    // 4. Verify sink received the transferred bytes
    assert_eq!(dispatcher.sink().as_slice(), message);

    // 5. Encode return into rax
    let mut rax = 0u64;
    encode_return(NtStatus::STATUS_SUCCESS, &mut rax);
    assert_eq!(rax, 0);

    // 6. Test NtTerminateProcess
    let terminate_call = NtCall::TerminateProcess {
        process_handle: NtHandle::CURRENT_PROCESS,
        exit_status: NtStatus::from_raw(0),
    };
    let term_flow = dispatcher.dispatch(&terminate_call);
    assert_eq!(term_flow, ControlFlow::Terminate(0));
}

// ============================================================================
// 5. Differential Oracle Conformance Verification
// ============================================================================

#[test]
fn test_differential_oracle_receipt_conformance() {
    // Read the committed Windows Server 2025 container oracle receipt
    let receipt_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/oracle/receipts/hello_console.json"
    );
    let receipt_json = std::fs::read_to_string(receipt_path)
        .expect("Committed oracle receipt tests/oracle/receipts/hello_console.json must exist");
    let receipt: serde_json::Value =
        serde_json::from_str(&receipt_json).expect("Receipt must be valid JSON");

    let expected_stdout = receipt["execution"]["stdout_raw"]
        .as_str()
        .expect("stdout_raw must be a string");
    let expected_exit_code = receipt["execution"]["exit_code"]
        .as_i64()
        .expect("exit_code must be an integer") as i32;

    assert_eq!(expected_stdout, "Hello, Carrick NT!\r\n");
    assert_eq!(expected_exit_code, 0);

    // Verify NtWriteFile produces the identical byte stream and NtTerminateProcess produces the identical exit code
    let mut memory = SimulatedUserMemory::new();
    let handle_table = HandleTable::with_standard_handles(1000, 1001);
    let sink = BufferOutputSink::new();

    let msg = expected_stdout.as_bytes();
    let buf_va = 0x0000_0001_4000_1000u64;
    let iosb_va = 0x0000_0001_4000_2000u64;
    memory.write_memory(buf_va, msg);
    memory.map_page(iosb_va, true, true);

    let mut dispatcher = NtDispatcher::new(handle_table, memory, sink);

    let write_call = NtCall::WriteFile {
        file_handle: NtHandle::STD_OUTPUT,
        event: NtHandle::NULL,
        apc_routine: GuestVa::NULL,
        apc_context: GuestVa::NULL,
        io_status_block: GuestPtr::from_raw(iosb_va),
        buffer: GuestVa::new(buf_va),
        length: UserLength::new(msg.len() as u32),
        byte_offset: GuestVa::NULL,
        key: GuestVa::NULL,
    };

    let flow = dispatcher.dispatch(&write_call);
    assert_eq!(flow, ControlFlow::Return(NtStatus::STATUS_SUCCESS));
    assert_eq!(dispatcher.sink().as_slice(), expected_stdout.as_bytes());

    let iosb = dispatcher
        .memory()
        .read_io_status_block(GuestPtr::from_raw(iosb_va))
        .expect("iosb read must succeed");
    assert_eq!(iosb.information, msg.len() as u64);
    assert_eq!(iosb.status, NtStatus::STATUS_SUCCESS);

    let term_call = NtCall::TerminateProcess {
        process_handle: NtHandle::CURRENT_PROCESS,
        exit_status: NtStatus::from_raw(expected_exit_code as u32),
    };
    let term_flow = dispatcher.dispatch(&term_call);
    assert_eq!(term_flow, ControlFlow::Terminate(expected_exit_code));
}
