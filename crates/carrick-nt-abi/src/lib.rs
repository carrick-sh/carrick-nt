//! Clean-room NT ABI wire types, status codes, and Carrick system call service IDs.
//!
//! Citations:
//! - docs/design/ntdll-bootstrap.md Section 2.3 & 6.4 (Milestone M2, Work Package NT-008)
//! - Microsoft Learn: NTSTATUS values, WDK headers
//! - Microsoft PE and COFF Specification (Rev 11.0)
//! - AGENTS.md clean-room rules: 100% clean-room, no Wine/ReactOS, no leaked Microsoft code.

#![no_std]

pub mod handle;
pub mod pointer;
pub mod service;
pub mod status;
pub mod wire;

// Re-export primary types for ease of use
pub use handle::NtHandle;
pub use pointer::{ByteCount, GuestPtr, GuestVa, UserLength};
pub use service::NtServiceId;
pub use status::NtStatus;
pub use wire::{
    eq_ignore_ascii_case_utf16, find_environment_variable, ClientId, CurDir, IoStatusBlock,
    ObjectAttributes, Peb, RtlUserProcessParameters, Teb, UnicodeString,
};

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn test_ntstatus_semantics() {
        assert!(NtStatus::STATUS_SUCCESS.is_success());
        assert!(!NtStatus::STATUS_SUCCESS.is_error());
        assert_eq!(NtStatus::STATUS_SUCCESS.as_u32(), 0);

        assert!(!NtStatus::STATUS_INVALID_HANDLE.is_success());
        assert!(NtStatus::STATUS_INVALID_HANDLE.is_error());
        assert_eq!(NtStatus::STATUS_INVALID_HANDLE.as_u32(), 0xC000_0008);

        assert!(!NtStatus::STATUS_END_OF_FILE.is_success());
        assert!(NtStatus::STATUS_END_OF_FILE.is_error());
        assert_eq!(NtStatus::STATUS_END_OF_FILE.as_u32(), 0xC000_0011);
    }

    #[test]
    fn test_nthandle_semantics() {
        assert!(NtHandle::NULL.is_null());
        assert!(NtHandle::NULL.is_invalid());
        assert!(NtHandle::INVALID.is_invalid());
        assert!(NtHandle::CURRENT_PROCESS.is_pseudo());
        assert!(NtHandle::CURRENT_THREAD.is_pseudo());
        assert!(NtHandle::STD_OUTPUT.is_pseudo());
        assert_eq!(NtHandle::CURRENT_PROCESS.as_u64(), 0xFFFF_FFFF_FFFF_FFFF);
        assert_eq!(NtHandle::STD_OUTPUT.as_u64(), 0xFFFF_FFFF_FFFF_FFF5);
    }

    #[test]
    fn test_nt_service_id_conversions() {
        assert_eq!(
            NtServiceId::from_u32(1),
            Some(NtServiceId::NtTerminateProcess)
        );
        assert_eq!(NtServiceId::from_u32(2), Some(NtServiceId::NtWriteFile));
        assert_eq!(NtServiceId::from_u32(3), Some(NtServiceId::NtClose));
        assert_eq!(NtServiceId::from_u32(0), None);
        assert_eq!(NtServiceId::from_u32(4), None);
    }

    #[test]
    fn test_wire_struct_layouts() {
        // Assert exact sizes and alignments matching x86_64 Windows NT standards
        assert_eq!(size_of::<IoStatusBlock>(), 16);
        assert_eq!(align_of::<IoStatusBlock>(), 8);
        assert_eq!(offset_of!(IoStatusBlock, status), 0);
        assert_eq!(offset_of!(IoStatusBlock, information), 8);

        assert_eq!(size_of::<UnicodeString>(), 16);
        assert_eq!(align_of::<UnicodeString>(), 8);
        assert_eq!(offset_of!(UnicodeString, length), 0);
        assert_eq!(offset_of!(UnicodeString, maximum_length), 2);
        assert_eq!(offset_of!(UnicodeString, buffer), 8);

        assert_eq!(size_of::<ObjectAttributes>(), 48);
        assert_eq!(align_of::<ObjectAttributes>(), 8);
        assert_eq!(offset_of!(ObjectAttributes, length), 0);
        assert_eq!(offset_of!(ObjectAttributes, root_directory), 8);
        assert_eq!(offset_of!(ObjectAttributes, object_name), 16);
        assert_eq!(offset_of!(ObjectAttributes, attributes), 24);
        assert_eq!(offset_of!(ObjectAttributes, security_descriptor), 32);
        assert_eq!(
            offset_of!(ObjectAttributes, security_quality_of_service),
            40
        );

        assert_eq!(size_of::<ClientId>(), 16);
        assert_eq!(align_of::<ClientId>(), 8);
        assert_eq!(offset_of!(ClientId, unique_process), 0);
        assert_eq!(offset_of!(ClientId, unique_thread), 8);

        assert_eq!(size_of::<CurDir>(), 24);
        assert_eq!(align_of::<CurDir>(), 8);
        assert_eq!(offset_of!(CurDir, dos_path), 0);
        assert_eq!(offset_of!(CurDir, handle), 16);

        assert_eq!(size_of::<RtlUserProcessParameters>(), 136);
        assert_eq!(align_of::<RtlUserProcessParameters>(), 8);
        assert_eq!(offset_of!(RtlUserProcessParameters, maximum_length), 0);
        assert_eq!(offset_of!(RtlUserProcessParameters, length), 4);
        assert_eq!(offset_of!(RtlUserProcessParameters, flags), 8);
        assert_eq!(offset_of!(RtlUserProcessParameters, debug_flags), 12);
        assert_eq!(offset_of!(RtlUserProcessParameters, console_handle), 16);
        assert_eq!(offset_of!(RtlUserProcessParameters, console_flags), 24);
        assert_eq!(offset_of!(RtlUserProcessParameters, standard_input), 32);
        assert_eq!(offset_of!(RtlUserProcessParameters, standard_output), 40);
        assert_eq!(offset_of!(RtlUserProcessParameters, standard_error), 48);
        assert_eq!(offset_of!(RtlUserProcessParameters, current_directory), 56);
        assert_eq!(offset_of!(RtlUserProcessParameters, dll_path), 80);
        assert_eq!(offset_of!(RtlUserProcessParameters, image_path_name), 96);
        assert_eq!(offset_of!(RtlUserProcessParameters, command_line), 112);
        assert_eq!(offset_of!(RtlUserProcessParameters, environment), 128);

        assert_eq!(size_of::<Peb>(), 40);
        assert_eq!(align_of::<Peb>(), 8);
        assert_eq!(offset_of!(Peb, being_debugged), 2);
        assert_eq!(offset_of!(Peb, mutant), 8);
        assert_eq!(offset_of!(Peb, image_base_address), 16);
        assert_eq!(offset_of!(Peb, loader_data), 24);
        assert_eq!(offset_of!(Peb, process_parameters), 32);

        assert_eq!(size_of::<Teb>(), 104);
        assert_eq!(align_of::<Teb>(), 8);
        assert_eq!(offset_of!(Teb, teb_self), 48);
        assert_eq!(offset_of!(Teb, client_id), 64);
        assert_eq!(offset_of!(Teb, process_environment_block), 96);
    }

    #[test]
    fn test_environment_variable_lookup() {
        // Build sample UTF-16 environment block:
        // "PATH=C:\\bin\0FOO=BarBaz\0=C:=C:\\\0\0"
        let mut env: [u16; 34] = [0; 34];
        let entries = "PATH=C:\\bin\0FOO=BarBaz\0=C:=C:\\\0\0";
        for (i, c) in entries.encode_utf16().enumerate() {
            env[i] = c;
        }

        let path_name: [u16; 4] = ['p' as u16, 'A' as u16, 't' as u16, 'H' as u16];
        let val = find_environment_variable(&env, &path_name);
        assert!(val.is_some());
        let expected_val: [u16; 6] = [
            'C' as u16,
            ':' as u16,
            '\\' as u16,
            'b' as u16,
            'i' as u16,
            'n' as u16,
        ];
        assert_eq!(val.unwrap(), &expected_val);

        let foo_name: [u16; 3] = ['f' as u16, 'o' as u16, 'o' as u16];
        let val = find_environment_variable(&env, &foo_name);
        assert!(val.is_some());
        let expected_foo: [u16; 6] = [
            'B' as u16, 'a' as u16, 'r' as u16, 'B' as u16, 'a' as u16, 'z' as u16,
        ];
        assert_eq!(val.unwrap(), &expected_foo);

        // Not found
        let missing: [u16; 4] = ['N' as u16, 'O' as u16, 'P' as u16, 'E' as u16];
        assert!(find_environment_variable(&env, &missing).is_none());

        // Empty environment
        let empty_env: [u16; 2] = [0, 0];
        assert!(find_environment_variable(&empty_env, &path_name).is_none());

        // Empty variable name
        assert!(find_environment_variable(&env, &[]).is_none());
    }
}
