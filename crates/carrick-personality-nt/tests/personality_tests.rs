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

use carrick_core::personality::{
    CallContext, CallOrdinal, EntryDecodeError, Personality, PersonalityAbi, ServiceError, TaskId,
    TaskKey, TaskSerial, ThreadKey,
};
use carrick_guest_arch::{
    Access, AddressContext, Arch, ArchTypes, CopyProgress, DefaultMmOwner, EntryBackend,
    EntryEvent, GuestIsa, GuestLen, KernelStackPointer, MmuBackend, NativeAbi, NativeEntrySnapshot,
    NativeReturnWord, ThreadPointerRegister, TransferDirection, UserRange, UserReturn, UserVa,
    X86Register, X86Registers,
};
use carrick_nt_abi::{GuestPtr, GuestVa, NtHandle, NtServiceId, NtStatus, UserLength};
use carrick_personality_nt::handle_table::access_rights;
use carrick_personality_nt::{
    encode_nt_status_return, encode_return, service_error_to_ntstatus, BufferOutputSink,
    CarrickUserMemory, ControlFlow, HandleObject, HandleTable, NtCall, NtDispatcher, NtFrame,
    NtPersonality, SimulatedUserMemory, UserMemory, NT_X64_STACK_ARG_BASE_OFFSET,
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

impl X86Registers for TestFrame {
    fn read(&self, register: X86Register) -> u64 {
        match register {
            X86Register::Rax => self.ordinal,
            X86Register::Rdi => self.reg_args[0],
            X86Register::Rsi => self.reg_args[1],
            X86Register::Rdx => self.reg_args[2],
            X86Register::R10 => self.reg_args[3],
            X86Register::R8 => self.reg_args[4],
            X86Register::R9 => self.reg_args[5],
            X86Register::Rsp => self.user_sp.raw(),
            _ => 0,
        }
    }
}

impl NtFrame for TestFrame {
    fn set_return_result(&mut self, result: NativeReturnWord) -> Result<(), EntryDecodeError> {
        self.rax = result.0;
        Ok(())
    }
}

struct TestUserTransfer {
    user: UserVa,
    kernel: core::ptr::NonNull<u8>,
    total: GuestLen,
    completed: GuestLen,
    direction: TransferDirection,
}

#[derive(Debug)]
struct TestEntryBackend {
    pages: HashMap<
        u64,
        (
            bool, /* readable */
            bool, /* writable */
            [u8; 4096],
        ),
    >,
    isa: GuestIsa,
    abi: NativeAbi,
}

impl Default for TestEntryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl TestEntryBackend {
    fn new() -> Self {
        Self {
            pages: HashMap::new(),
            isa: GuestIsa::X86_64,
            abi: NativeAbi::X86_64Syscall,
        }
    }

    fn with_isa(mut self, isa: GuestIsa, abi: NativeAbi) -> Self {
        self.isa = isa;
        self.abi = abi;
        self
    }

    fn map_page(&mut self, va: u64, readable: bool) {
        self.map_page_with_perms(va, readable, false);
    }

    fn map_page_with_perms(&mut self, va: u64, readable: bool, writable: bool) {
        let page_base = va & !0xfff;
        let entry = self
            .pages
            .entry(page_base)
            .or_insert((readable, writable, [0u8; 4096]));
        entry.0 = readable;
        entry.1 = writable;
    }

    fn write_u64(&mut self, va: u64, val: u64) {
        let page_base = va & !0xfff;
        let offset = (va & 0xfff) as usize;
        let entry = self
            .pages
            .entry(page_base)
            .or_insert((true, true, [0u8; 4096]));
        if offset + 8 <= 4096 {
            entry.2[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
        }
    }

    fn write_bytes(&mut self, va: u64, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            let addr = va + i as u64;
            let page_base = addr & !0xfff;
            let offset = (addr & 0xfff) as usize;
            let entry = self
                .pages
                .entry(page_base)
                .or_insert((true, true, [0u8; 4096]));
            entry.2[offset] = b;
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
    type UserTransfer = TestUserTransfer;
    type HardwareInterrupt = u32;
    type InterruptMask = u32;
}

impl DefaultMmOwner for TestEntryBackend {
    fn default_owner() -> Option<&'static Self::MmOwner> {
        static DEFAULT_OWNER: () = ();
        Some(&DEFAULT_OWNER)
    }
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
        frame: &'a Self::NativeFrame,
    ) -> Result<NativeEntrySnapshot<'a, Self::NativeFrame>, Self::Error> {
        Ok(NativeEntrySnapshot {
            isa: self.isa,
            abi: self.abi,
            frame,
        })
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
        let va = frame.user_sp.raw();
        let page_base = va & !0xfff;
        let page = self.pages.get(&page_base).ok_or(EntryDecodeError::Fault)?;
        if !page.0 {
            return Err(EntryDecodeError::Fault);
        }
        Ok(frame.user_sp)
    }
}

impl MmuBackend for TestEntryBackend {
    fn live_root(&mut self) -> Result<Self::Root, Self::Error> {
        Ok(0)
    }

    fn read_user_word(
        &mut self,
        _owner: &Self::MmOwner,
        address: UserVa,
        width: GuestLen,
    ) -> Result<u64, Self::Error> {
        let va = address.raw();
        let page_base = va & !0xfff;
        let page_offset = (va & 0xfff) as usize;
        let page = self.pages.get(&page_base).ok_or(EntryDecodeError::Fault)?;
        if !page.0 {
            return Err(EntryDecodeError::Fault);
        }
        match width.raw() {
            4 => {
                if page_offset + 4 > 4096 {
                    return Err(EntryDecodeError::Fault);
                }
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(&page.2[page_offset..page_offset + 4]);
                Ok(u32::from_le_bytes(bytes) as u64)
            }
            8 => {
                if page_offset + 8 > 4096 {
                    return Err(EntryDecodeError::Fault);
                }
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&page.2[page_offset..page_offset + 8]);
                Ok(u64::from_le_bytes(bytes))
            }
            _ => Err(EntryDecodeError::InvalidWidth),
        }
    }

    fn validate_user_access(
        &mut self,
        _owner: &Self::MmOwner,
        range: UserRange,
        access: Access,
    ) -> Result<GuestLen, Self::Error> {
        if !range.in_lower_half() {
            return Ok(GuestLen::new(0));
        }
        let start = range.start().raw();
        let len = range.len().raw();
        let mut checked = 0u64;
        while checked < len {
            let addr = start + checked;
            let page_base = addr & !0xfff;
            let page_offset = (addr & 0xfff) as usize;
            let page_rem = (4096 - page_offset) as u64;
            let step = (len - checked).min(page_rem);
            let Some(page) = self.pages.get(&page_base) else {
                break;
            };
            let allowed = match access {
                Access::Read => page.0,
                Access::Write => page.1,
                Access::Execute => false,
            };
            if !allowed {
                break;
            }
            checked += step;
        }
        Ok(GuestLen::new(checked))
    }

    fn install_context(&mut self, _context: AddressContext<Self::Root>) -> Result<(), Self::Error> {
        Ok(())
    }

    fn request_invalidation(
        &mut self,
        _context: AddressContext<Self::Root>,
        _range: UserRange,
    ) -> Result<Self::DrainTicket, Self::Error> {
        Ok(())
    }

    fn ack_drain(&mut self, _ticket: Self::DrainTicket) -> Result<Self::DrainReceipt, Self::Error> {
        Ok(())
    }

    fn open_user_transfer(
        &mut self,
        _owner: &Self::MmOwner,
        user: UserVa,
        kernel: core::ptr::NonNull<u8>,
        len: GuestLen,
        direction: TransferDirection,
    ) -> Result<Self::UserTransfer, Self::Error> {
        let range = UserRange::checked(user, len).ok_or(EntryDecodeError::OutOfBounds)?;
        if !range.in_lower_half() {
            return Err(EntryDecodeError::OutOfBounds);
        }
        Ok(TestUserTransfer {
            user,
            kernel,
            total: len,
            completed: GuestLen::new(0),
            direction,
        })
    }

    fn copy_user_chunk(
        &mut self,
        transfer: &mut Self::UserTransfer,
        limit: GuestLen,
    ) -> Result<CopyProgress, Self::Error> {
        let remaining = transfer.total.raw() - transfer.completed.raw();
        if remaining == 0 || limit.raw() == 0 {
            return Ok(CopyProgress {
                completed: GuestLen::new(0),
                remaining: GuestLen::new(remaining),
            });
        }
        let cur_va = transfer.user.raw() + transfer.completed.raw();
        let page_base = cur_va & !0xfff;
        let page_offset = (cur_va & 0xfff) as usize;
        let page_remaining = 4096 - page_offset;
        let chunk_len = (limit.raw().min(remaining).min(page_remaining as u64)) as usize;

        let page = self
            .pages
            .get_mut(&page_base)
            .ok_or(EntryDecodeError::Fault)?;
        match transfer.direction {
            TransferDirection::FromUser => {
                if !page.0 {
                    return Err(EntryDecodeError::Fault);
                }
                unsafe {
                    let kptr = transfer
                        .kernel
                        .as_ptr()
                        .add(transfer.completed.raw() as usize);
                    core::ptr::copy_nonoverlapping(&page.2[page_offset], kptr, chunk_len);
                }
            }
            TransferDirection::ToUser => {
                if !page.1 {
                    return Err(EntryDecodeError::Fault);
                }
                unsafe {
                    let kptr = transfer
                        .kernel
                        .as_ptr()
                        .add(transfer.completed.raw() as usize);
                    core::ptr::copy_nonoverlapping(kptr, &mut page.2[page_offset], chunk_len);
                }
            }
        }
        transfer.completed = GuestLen::new(transfer.completed.raw() + chunk_len as u64);
        let new_remaining = transfer.total.raw() - transfer.completed.raw();
        Ok(CopyProgress {
            completed: GuestLen::new(chunk_len as u64),
            remaining: GuestLen::new(new_remaining),
        })
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
        decoded.ordinal(),
        CallOrdinal::from_raw(NtServiceId::NtTerminateProcess.as_u32() as u64)
    );
    match decoded {
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
    assert_eq!(
        decoded.ordinal(),
        CallOrdinal::from_raw(NtServiceId::NtClose.as_u32() as u64)
    );
    assert_eq!(
        decoded,
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

    assert_eq!(
        decoded.ordinal(),
        CallOrdinal::from_raw(NtServiceId::NtWriteFile.as_u32() as u64)
    );
    match decoded {
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
fn test_decode_unsupported_isa_returns_unsupported() {
    let personality = NtPersonality::new();
    let backend = TestEntryBackend::new().with_isa(GuestIsa::Aarch64, NativeAbi::Aarch64El0);
    let frame = backend.create_frame(NtServiceId::NtClose, [0; 6], 0x7000_0000);
    let mut arch = Arch::new(backend);
    let mut cx = CallContext::new(&mut arch, &frame);

    let err = personality.decode(&mut cx);
    assert_eq!(err, Err(EntryDecodeError::UnsupportedAbi));
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

    // 2. Dispatch NtWriteFile
    let mut dispatcher = NtDispatcher::new(handle_table, memory, sink);
    let flow = dispatcher.dispatch(&decoded);
    assert_eq!(flow, ControlFlow::Return(NtStatus::STATUS_SUCCESS));

    // 3. Verify IO_STATUS_BLOCK updated in guest memory
    let iosb = dispatcher
        .memory_mut()
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
        .memory_mut()
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

// ============================================================================
// 6. CarrickUserMemory Adapter and Error Mapping Tests
// ============================================================================

#[test]
fn test_service_error_to_ntstatus_mapping() {
    assert_eq!(
        service_error_to_ntstatus(ServiceError::Fault),
        NtStatus::STATUS_ACCESS_VIOLATION
    );
    assert_eq!(
        service_error_to_ntstatus(ServiceError::AccessDenied),
        NtStatus::STATUS_ACCESS_VIOLATION
    );
    assert_eq!(
        service_error_to_ntstatus(ServiceError::RangeOverflow),
        NtStatus::STATUS_ACCESS_VIOLATION
    );
    assert_eq!(
        service_error_to_ntstatus(ServiceError::Refused),
        NtStatus::STATUS_UNSUCCESSFUL
    );
}

#[test]
fn test_carrick_user_memory_read_write_and_faults() {
    let mut backend = TestEntryBackend::new();
    let read_page = 0x0000_0000_1000_0000u64;
    let write_page = 0x0000_0000_2000_0000u64;
    let ro_page = 0x0000_0000_3000_0000u64;

    backend.map_page_with_perms(read_page, true, false); // read-only
    backend.map_page_with_perms(write_page, true, true); // read-write
    backend.map_page_with_perms(ro_page, true, false); // read-only

    let test_data = b"Hello, Carrick NT user memory!";
    backend.write_bytes(read_page + 64, test_data);

    let frame = backend.create_frame(NtServiceId::NtClose, [0; 6], 0x7000_0000);
    let mut arch = Arch::new(backend);
    let mut cx = CallContext::new(&mut arch, &frame);

    let mut user_mem = CarrickUserMemory::new(cx.user());

    // 1. Successful read
    let mut read_buf = [0u8; 30];
    let res = user_mem.read_bytes(GuestVa::new(read_page + 64), &mut read_buf);
    assert_eq!(res, Ok(()));
    assert_eq!(&read_buf, test_data);

    // 2. Read empty buffer
    let mut empty_buf = [];
    assert_eq!(
        user_mem.read_bytes(GuestVa::new(0x0000_0000_1000_0000), &mut empty_buf),
        Ok(())
    );

    // 3. Read from unmapped address returns STATUS_ACCESS_VIOLATION
    let mut unmapped_buf = [0u8; 16];
    let unmapped_res = user_mem.read_bytes(GuestVa::new(0x0000_0000_9000_0000), &mut unmapped_buf);
    assert_eq!(unmapped_res, Err(NtStatus::STATUS_ACCESS_VIOLATION));

    // 4. Successful write to writable page
    let write_payload = b"Testing write_bytes into writable page";
    let write_res = user_mem.write_bytes(GuestVa::new(write_page + 128), write_payload);
    assert_eq!(write_res, Ok(()));

    // Read back written data
    let mut read_back = vec![0u8; write_payload.len()];
    assert_eq!(
        user_mem.read_bytes(GuestVa::new(write_page + 128), &mut read_back),
        Ok(())
    );
    assert_eq!(&read_back[..], write_payload);

    // 5. Write to read-only page returns STATUS_ACCESS_VIOLATION
    let ro_write_res = user_mem.write_bytes(GuestVa::new(ro_page), b"should fail");
    assert_eq!(ro_write_res, Err(NtStatus::STATUS_ACCESS_VIOLATION));

    // 6. Range overflow (canonical upper half or wrap) returns STATUS_ACCESS_VIOLATION
    let overflow_res = user_mem.read_bytes(GuestVa::new(0xFFFF_8000_0000_0000), &mut read_buf);
    assert_eq!(overflow_res, Err(NtStatus::STATUS_ACCESS_VIOLATION));
}

#[test]
fn test_read_nt_argument_all_slots() {
    let mut backend = TestEntryBackend::new();
    let stack_va = 0x0000_7FFF_1000u64;
    backend.map_page(stack_va, true);

    // Map stack args (args 4..8) at [rsp + 0x28 + 8*i]
    backend.write_u64(stack_va + NT_X64_STACK_ARG_BASE_OFFSET, 104);
    backend.write_u64(stack_va + NT_X64_STACK_ARG_BASE_OFFSET + 8, 105);
    backend.write_u64(stack_va + NT_X64_STACK_ARG_BASE_OFFSET + 16, 106);
    backend.write_u64(stack_va + NT_X64_STACK_ARG_BASE_OFFSET + 24, 107);
    backend.write_u64(stack_va + NT_X64_STACK_ARG_BASE_OFFSET + 32, 108);

    let reg_args = [
        10, 20, 101, /* rdx */
        100, /* r10 */
        102, /* r8 */
        103, /* r9 */
    ];
    let frame = backend.create_frame(NtServiceId::NtWriteFile, reg_args, stack_va);
    let mut arch = Arch::new(backend);
    let mut cx = CallContext::new(&mut arch, &frame);

    // Register arguments:
    assert_eq!(
        carrick_personality_nt::read_nt_argument(&mut cx, 0).unwrap(),
        100
    );
    assert_eq!(
        carrick_personality_nt::read_nt_argument(&mut cx, 1).unwrap(),
        101
    );
    assert_eq!(
        carrick_personality_nt::read_nt_argument(&mut cx, 2).unwrap(),
        102
    );
    assert_eq!(
        carrick_personality_nt::read_nt_argument(&mut cx, 3).unwrap(),
        103
    );

    // Stack arguments:
    assert_eq!(
        carrick_personality_nt::read_nt_argument(&mut cx, 4).unwrap(),
        104
    );
    assert_eq!(
        carrick_personality_nt::read_nt_argument(&mut cx, 5).unwrap(),
        105
    );
    assert_eq!(
        carrick_personality_nt::read_nt_argument(&mut cx, 6).unwrap(),
        106
    );
    assert_eq!(
        carrick_personality_nt::read_nt_argument(&mut cx, 7).unwrap(),
        107
    );
    assert_eq!(
        carrick_personality_nt::read_nt_argument(&mut cx, 8).unwrap(),
        108
    );
}

#[test]
fn test_read_nt_argument_stack_faults() {
    let backend = TestEntryBackend::new();
    let unmapped_sp = 0xDEAD_BEEF_0000u64;
    let frame = backend.create_frame(NtServiceId::NtWriteFile, [0; 6], unmapped_sp);
    let mut arch = Arch::new(backend);
    let mut cx = CallContext::new(&mut arch, &frame);

    // Reading arg 4 from unmapped stack must return EntryDecodeError::Fault
    let err = carrick_personality_nt::read_nt_argument(&mut cx, 4);
    assert_eq!(err, Err(EntryDecodeError::Fault));
}

#[test]
fn test_dispatch_nt_write_file_with_carrick_user_memory() {
    let mut backend = TestEntryBackend::new();

    let stack_va = 0x0000_0000_7000_8000u64;
    let buf_va = 0x0000_0000_5000_1000u64;
    let iosb_va = 0x0000_0000_5000_2000u64;

    let payload = b"Data processed through CarrickUserMemory adapter!";

    // Backend pages
    backend.map_page_with_perms(stack_va, true, false); // stack
    backend.map_page_with_perms(buf_va, true, false); // input buffer (readable)
    backend.map_page_with_perms(iosb_va, true, true); // IO_STATUS_BLOCK (writable)

    backend.write_bytes(buf_va, payload);

    // Spilled arguments on stack
    backend.write_u64(stack_va + NT_X64_STACK_ARG_BASE_OFFSET, iosb_va);
    backend.write_u64(stack_va + NT_X64_STACK_ARG_BASE_OFFSET + 8, buf_va);
    backend.write_u64(
        stack_va + NT_X64_STACK_ARG_BASE_OFFSET + 16,
        payload.len() as u64,
    );
    backend.write_u64(stack_va + NT_X64_STACK_ARG_BASE_OFFSET + 24, 0);
    backend.write_u64(stack_va + NT_X64_STACK_ARG_BASE_OFFSET + 32, 0);

    let handle_table = HandleTable::with_standard_handles(100, 101);
    let stdout_handle = NtHandle::STD_OUTPUT;

    let mut reg_args = [0u64; 6];
    reg_args[3] = stdout_handle.as_u64(); // r10 = file_handle
    reg_args[2] = 0; // rdx = event
    reg_args[4] = 0; // r8 = apc_routine
    reg_args[5] = 0; // r9 = apc_context

    let frame = backend.create_frame(NtServiceId::NtWriteFile, reg_args, stack_va);
    let mut arch = Arch::new(backend);
    let mut cx = CallContext::new(&mut arch, &frame);

    let personality = NtPersonality::new();
    let decoded = personality.decode(&mut cx).expect("decode must succeed");

    let sink = BufferOutputSink::new();
    let memory = CarrickUserMemory::new(cx.user());
    let mut dispatcher = NtDispatcher::new(handle_table, memory, sink);

    let flow = dispatcher.dispatch(&decoded);
    assert_eq!(flow, ControlFlow::Return(NtStatus::STATUS_SUCCESS));
    assert_eq!(dispatcher.sink().as_slice(), payload);

    // Verify IO_STATUS_BLOCK read back through CarrickUserMemory
    let mut iosb_bytes = [0u8; 16];
    dispatcher
        .memory_mut()
        .read_bytes(GuestVa::new(iosb_va), &mut iosb_bytes)
        .expect("read iosb must succeed");
    let status_val = u32::from_le_bytes(iosb_bytes[0..4].try_into().unwrap());
    let info_val = u64::from_le_bytes(iosb_bytes[8..16].try_into().unwrap());
    assert_eq!(status_val, NtStatus::STATUS_SUCCESS.as_u32());
    assert_eq!(info_val, payload.len() as u64);
}

#[test]
fn test_dispatch_nt_write_file_faults_on_unmapped_buffer() {
    let mut backend = TestEntryBackend::new();
    let stack_va = 0x0000_0000_7000_8000u64;
    let unmapped_buf_va = 0x0000_0000_9000_0000u64;
    let iosb_va = 0x0000_0000_5000_2000u64;

    backend.map_page_with_perms(stack_va, true, false);
    backend.map_page_with_perms(iosb_va, true, true);

    let frame = backend.create_frame(NtServiceId::NtWriteFile, [0; 6], stack_va);
    let mut arch = Arch::new(backend);
    let mut cx = CallContext::new(&mut arch, &frame);

    let handle_table = HandleTable::with_standard_handles(100, 101);
    let sink = BufferOutputSink::new();
    let memory = CarrickUserMemory::new(cx.user());
    let mut dispatcher = NtDispatcher::new(handle_table, memory, sink);

    let call = NtCall::WriteFile {
        file_handle: NtHandle::STD_OUTPUT,
        event: NtHandle::NULL,
        apc_routine: GuestVa::NULL,
        apc_context: GuestVa::NULL,
        io_status_block: GuestPtr::from_raw(iosb_va),
        buffer: GuestVa::new(unmapped_buf_va),
        length: UserLength::new(64),
        byte_offset: GuestVa::NULL,
        key: GuestVa::NULL,
    };

    let flow = dispatcher.dispatch(&call);
    assert_eq!(flow, ControlFlow::Return(NtStatus::STATUS_ACCESS_VIOLATION));
}

#[test]
fn test_dispatch_nt_write_file_faults_on_unwritable_iosb() {
    let mut backend = TestEntryBackend::new();
    let stack_va = 0x0000_0000_7000_8000u64;
    let buf_va = 0x0000_0000_5000_1000u64;
    let ro_iosb_va = 0x0000_0000_5000_2000u64;

    backend.map_page_with_perms(stack_va, true, false);
    backend.map_page_with_perms(buf_va, true, false);
    backend.map_page_with_perms(ro_iosb_va, true, false); // read-only!

    backend.write_bytes(buf_va, b"valid message");

    let frame = backend.create_frame(NtServiceId::NtWriteFile, [0; 6], stack_va);
    let mut arch = Arch::new(backend);
    let mut cx = CallContext::new(&mut arch, &frame);

    let handle_table = HandleTable::with_standard_handles(100, 101);
    let sink = BufferOutputSink::new();
    let memory = CarrickUserMemory::new(cx.user());
    let mut dispatcher = NtDispatcher::new(handle_table, memory, sink);

    let call = NtCall::WriteFile {
        file_handle: NtHandle::STD_OUTPUT,
        event: NtHandle::NULL,
        apc_routine: GuestVa::NULL,
        apc_context: GuestVa::NULL,
        io_status_block: GuestPtr::from_raw(ro_iosb_va),
        buffer: GuestVa::new(buf_va),
        length: UserLength::new(13),
        byte_offset: GuestVa::NULL,
        key: GuestVa::NULL,
    };

    let flow = dispatcher.dispatch(&call);
    assert_eq!(flow, ControlFlow::Return(NtStatus::STATUS_ACCESS_VIOLATION));
}

#[test]
fn test_typed_keys_and_encode_return() {
    let personality = NtPersonality::new();

    // CallOrdinal
    let ordinal = CallOrdinal::from_raw(0x1234);
    assert_eq!(ordinal.raw(), 0x1234);

    let write_call = NtCall::WriteFile {
        file_handle: NtHandle::NULL,
        event: NtHandle::NULL,
        apc_routine: GuestVa::NULL,
        apc_context: GuestVa::NULL,
        io_status_block: GuestPtr::from_raw(0),
        buffer: GuestVa::NULL,
        length: UserLength::new(0),
        byte_offset: GuestVa::NULL,
        key: GuestVa::NULL,
    };
    assert_eq!(
        write_call.ordinal(),
        CallOrdinal::from_raw(NtServiceId::NtWriteFile.as_u32() as u64)
    );

    // ThreadKey and TaskKey with NtPersonality
    let thread_key = ThreadKey::new(100, 2);
    assert_eq!(thread_key.id(), 100);
    assert_eq!(thread_key.generation(), 2);
    assert_eq!(
        personality.thread_pointer_register_for_thread(thread_key),
        ThreadPointerRegister::GS
    );

    let task_key = TaskKey {
        id: TaskId::from_abi_positive(50).expect("valid task id"),
        serial: TaskSerial::from_raw_u64(1).expect("valid serial"),
    };
    assert_eq!(
        personality.thread_pointer_register_for_task(task_key),
        ThreadPointerRegister::GS
    );

    // encode_return on PersonalityAbi
    let backend = TestEntryBackend::new();
    let mut frame = backend.create_frame(NtServiceId::NtClose, [0; 6], 0x7000_0000);

    PersonalityAbi::<Arch<TestEntryBackend>>::encode_return(
        &personality,
        NativeReturnWord(NtStatus::STATUS_ACCESS_VIOLATION.as_u32() as u64),
        &mut frame,
    )
    .expect("encode_return must succeed");
    assert_eq!(frame.rax, NtStatus::STATUS_ACCESS_VIOLATION.as_u32() as u64);

    // encode_nt_status_return
    encode_nt_status_return(NtStatus::STATUS_SUCCESS, &mut frame)
        .expect("encode_nt_status_return must succeed");
    assert_eq!(frame.rax, 0);
}
