//! Clean-room Windows NT personality for Carrick.
//!
//! Citations:
//! - docs/design/ntdll-bootstrap.md Section 2.3 & 4.2
//! - Microsoft Learn: WDK Native APIs & x64 Software Conventions
//! - AGENTS.md clean-room rules: 100% clean-room, no Wine/ReactOS, no leaked Microsoft code.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

extern crate alloc;

pub mod call;
pub mod carrick_memory;
pub mod decode;
pub mod dispatch;
pub mod handle_table;
pub mod memory;

pub use call::NtCall;
pub use carrick_memory::service_error_to_ntstatus;
pub use decode::{decode_nt_call, read_nt_argument, NT_X64_STACK_ARG_BASE_OFFSET};
#[cfg(feature = "std")]
pub use dispatch::StdOutputSink;
pub use dispatch::{
    encode_nt_status_return, encode_return, BufferOutputSink, ControlFlow, NtDispatcher, OutputSink,
};
pub use handle_table::{access_rights, HandleEntry, HandleObject, HandleTable};
#[cfg(any(test, feature = "test-support"))]
pub use memory::SimulatedUserMemory;
pub use memory::UserMemory;

use carrick_core::personality::{
    CallContext, EntryDecodeError, Personality, PersonalityAbi, ServiceError, TaskKey, ThreadKey,
};
use carrick_guest_arch::{
    DefaultMmOwner, EntryArch, MmuArch, NativeReturnWord, SyscallFrame, ThreadPointerRegister,
    X86Registers,
};

/// Extension trait for native execution frames capable of returning execution results for NT.
pub trait NtFrame: X86Registers {
    /// Encodes the NT system call return result word into the native frame.
    fn set_return_result(&mut self, result: NativeReturnWord) -> Result<(), EntryDecodeError>;
}

impl<T: X86Registers + SyscallFrame> NtFrame for T {
    fn set_return_result(&mut self, result: NativeReturnWord) -> Result<(), EntryDecodeError> {
        self.set_result(result);
        Ok(())
    }
}

/// Clean-room Windows NT operating system personality for Carrick.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NtPersonality;

impl NtPersonality {
    /// Creates a new `NtPersonality` instance.
    pub const fn new() -> Self {
        Self
    }
}

impl Personality for NtPersonality {
    fn name(&self) -> &'static str {
        "nt"
    }

    fn thread_pointer_register(&self) -> ThreadPointerRegister {
        ThreadPointerRegister::GS
    }

    fn thread_pointer_register_for_thread(&self, _thread: ThreadKey) -> ThreadPointerRegister {
        ThreadPointerRegister::GS
    }

    fn thread_pointer_register_for_task(&self, _task: TaskKey) -> ThreadPointerRegister {
        ThreadPointerRegister::GS
    }
}

impl<A: EntryArch + MmuArch + DefaultMmOwner> PersonalityAbi<A> for NtPersonality
where
    A::NativeFrame: NtFrame,
    EntryDecodeError: From<A::Error>,
    ServiceError: From<A::Error>,
{
    type Call = NtCall;

    fn decode(&self, cx: &mut CallContext<'_, A>) -> Result<Self::Call, EntryDecodeError> {
        decode_nt_call(cx)
    }

    fn encode_return(
        &self,
        result: NativeReturnWord,
        frame: &mut A::NativeFrame,
    ) -> Result<(), EntryDecodeError> {
        frame.set_return_result(result)
    }
}
