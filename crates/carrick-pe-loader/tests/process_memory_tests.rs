//! Tests for NT-007: PEB, TEB, and RTL_USER_PROCESS_PARAMETERS memory layout.
//!
//! Validates offsets and structures against Microsoft Learn / winternl.h:
//! - TEB: Self pointer at GS:[0x30], ClientId at GS:[0x40], PEB pointer at GS:[0x60]
//! - PEB: BeingDebugged at 0x02, ImageBaseAddress at 0x10, ProcessParameters at 0x20
//! - ProcessParameters: StandardOutput at 0x28, ImagePathName at 0x60, CommandLine at 0x70

use carrick_pe_loader::plan::VirtualAddress;
use carrick_pe_loader::process_memory::{
    ProcessMemoryConfig, ProcessMemoryImage, PEB_OFFSET_BEING_DEBUGGED,
    PROCESS_PARAMS_OFFSET_COMMAND_LINE, PROCESS_PARAMS_OFFSET_IMAGE_PATH,
    PROCESS_PARAMS_OFFSET_STD_ERR, PROCESS_PARAMS_OFFSET_STD_IN, STD_ERROR_HANDLE_VAL,
    STD_INPUT_HANDLE_VAL, STD_OUTPUT_HANDLE_VAL, TEB_OFFSET_CLIENT_ID_PID,
    TEB_OFFSET_CLIENT_ID_TID,
};

#[test]
fn test_process_memory_layout_conformance() {
    let teb_va = VirtualAddress::new(0x0000_7FFE_1000_0000);
    let peb_va = VirtualAddress::new(0x0000_7FFE_2000_0000);
    let params_va = VirtualAddress::new(0x0000_7FFE_3000_0000);
    let image_base = VirtualAddress::new(0x0000_0001_4000_0000);

    let config = ProcessMemoryConfig {
        teb_va,
        peb_va,
        process_parameters_va: params_va,
        image_base,
        image_path: "C:\\hello_console.exe",
        command_line: "hello_console.exe",
        stdin_handle: STD_INPUT_HANDLE_VAL,
        stdout_handle: STD_OUTPUT_HANDLE_VAL,
        stderr_handle: STD_ERROR_HANDLE_VAL,
        process_id: 4242,
        thread_id: 1337,
    };

    let image = ProcessMemoryImage::build(&config);

    // 1. Validate TEB (winternl.h)
    // GS:[0x30] must equal TEB guest virtual address (Self pointer)
    assert_eq!(image.read_teb_self(), teb_va.as_u64());

    // GS:[0x40] ClientId: UniqueProcess and UniqueThread
    let pid = u64::from_le_bytes(
        image.teb_bytes[TEB_OFFSET_CLIENT_ID_PID..TEB_OFFSET_CLIENT_ID_PID + 8]
            .try_into()
            .unwrap(),
    );
    let tid = u64::from_le_bytes(
        image.teb_bytes[TEB_OFFSET_CLIENT_ID_TID..TEB_OFFSET_CLIENT_ID_TID + 8]
            .try_into()
            .unwrap(),
    );
    assert_eq!(pid, 4242);
    assert_eq!(tid, 1337);

    // GS:[0x60] ProcessEnvironmentBlock must equal PEB VA
    assert_eq!(image.read_teb_peb(), peb_va.as_u64());

    // 2. Validate PEB (winternl.h)
    // Offset 0x02: BeingDebugged
    assert_eq!(image.peb_bytes[PEB_OFFSET_BEING_DEBUGGED], 0);

    // Offset 0x10: ImageBaseAddress
    assert_eq!(image.read_peb_image_base(), image_base.as_u64());

    // Offset 0x20: ProcessParameters
    assert_eq!(image.read_peb_process_parameters(), params_va.as_u64());

    // 3. Validate RTL_USER_PROCESS_PARAMETERS (winternl.h)
    // Offsets 0x20, 0x28, 0x30: Standard Handles
    let stdin_val = u64::from_le_bytes(
        image.process_parameters_bytes
            [PROCESS_PARAMS_OFFSET_STD_IN..PROCESS_PARAMS_OFFSET_STD_IN + 8]
            .try_into()
            .unwrap(),
    );
    assert_eq!(stdin_val, STD_INPUT_HANDLE_VAL);

    assert_eq!(image.read_standard_output_handle(), STD_OUTPUT_HANDLE_VAL);

    let stderr_val = u64::from_le_bytes(
        image.process_parameters_bytes
            [PROCESS_PARAMS_OFFSET_STD_ERR..PROCESS_PARAMS_OFFSET_STD_ERR + 8]
            .try_into()
            .unwrap(),
    );
    assert_eq!(stderr_val, STD_ERROR_HANDLE_VAL);

    // Offset 0x60: ImagePathName UNICODE_STRING
    let img_path_len = u16::from_le_bytes(
        image.process_parameters_bytes
            [PROCESS_PARAMS_OFFSET_IMAGE_PATH..PROCESS_PARAMS_OFFSET_IMAGE_PATH + 2]
            .try_into()
            .unwrap(),
    );
    let img_path_buffer_va = u64::from_le_bytes(
        image.process_parameters_bytes
            [PROCESS_PARAMS_OFFSET_IMAGE_PATH + 8..PROCESS_PARAMS_OFFSET_IMAGE_PATH + 16]
            .try_into()
            .unwrap(),
    );
    assert_eq!(img_path_len as usize, "C:\\hello_console.exe".len() * 2);
    assert!(img_path_buffer_va >= params_va.as_u64());

    // Offset 0x70: CommandLine UNICODE_STRING
    let cmd_len = u16::from_le_bytes(
        image.process_parameters_bytes
            [PROCESS_PARAMS_OFFSET_COMMAND_LINE..PROCESS_PARAMS_OFFSET_COMMAND_LINE + 2]
            .try_into()
            .unwrap(),
    );
    let cmd_buffer_va = u64::from_le_bytes(
        image.process_parameters_bytes
            [PROCESS_PARAMS_OFFSET_COMMAND_LINE + 8..PROCESS_PARAMS_OFFSET_COMMAND_LINE + 16]
            .try_into()
            .unwrap(),
    );
    assert_eq!(cmd_len as usize, "hello_console.exe".len() * 2);
    assert!(cmd_buffer_va >= params_va.as_u64());
}
