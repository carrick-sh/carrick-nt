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
        environment: &[("FOO", "BAR"), ("PATH", "C:\\bin")],
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
    assert_eq!(
        img_path_buffer_va % 8,
        0,
        "image_path_buffer_va must be 8-byte aligned"
    );

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
    assert_eq!(cmd_buffer_va % 8, 0, "cmd_buffer_va must be 8-byte aligned");

    // Offset 0x80: Environment pointer
    let env_ptr = image.read_environment_ptr();
    assert!(env_ptr >= params_va.as_u64());
    assert_eq!(env_ptr % 8, 0, "env_ptr must be 8-byte aligned");
}

#[test]
fn test_encoder_utf16_and_lengths_bytes_vs_chars() {
    // Tests that length is in BYTES (not UTF-16 code units / chars)
    let cmd = "myapp.exe --flag argument";
    let (length_bytes, max_length_bytes, raw_bytes) = carrick_pe_loader::encode_command_line(cmd);

    let char_count = cmd.chars().count();
    assert_eq!(length_bytes as usize, char_count * 2);
    assert_eq!(max_length_bytes as usize, (char_count + 1) * 2);
    assert_ne!(
        length_bytes as usize, char_count,
        "Length must be in bytes, not chars!"
    );
    assert_eq!(raw_bytes.len(), (char_count + 1) * 2);

    // Verify null terminator at end
    let trailing_u16 = u16::from_le_bytes(raw_bytes[raw_bytes.len() - 2..].try_into().unwrap());
    assert_eq!(trailing_u16, 0);

    // Verify first code unit
    let first_u16 = u16::from_le_bytes(raw_bytes[0..2].try_into().unwrap());
    assert_eq!(first_u16, b'm' as u16);
}

#[test]
fn test_encoder_empty_environment_block() {
    // An empty environment block in Windows NT must be double-null terminated ("\0\0" = 4 zero bytes)
    let env_bytes = carrick_pe_loader::encode_environment_block::<&str, &str>(&[]);
    assert_eq!(
        env_bytes.len(),
        4,
        "Empty environment block must be 4 bytes (2 UTF-16 nulls)"
    );
    assert_eq!(env_bytes, vec![0, 0, 0, 0]);

    // Build ProcessMemoryImage with empty environment
    let config = ProcessMemoryConfig {
        environment: &[],
        ..ProcessMemoryConfig::default()
    };
    let image = ProcessMemoryImage::build(&config);

    let env_va = image.read_environment_ptr();
    assert_eq!(env_va % 8, 0, "Environment pointer must be 8-byte aligned");

    let offset = (env_va - config.process_parameters_va.as_u64()) as usize;
    let env_slice = &image.process_parameters_bytes[offset..offset + 4];
    assert_eq!(env_slice, &[0, 0, 0, 0]);
}

#[test]
fn test_encoder_environment_pairs_and_double_nul_termination() {
    let vars = [("VAR1", "VALUE1"), ("KEY_TWO", "VALUE_TWO"), ("EMPTY", "")];
    let env_bytes = carrick_pe_loader::encode_environment_block(&vars);

    // Decode u16s
    let u16_units: Vec<u16> = env_bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes(c.try_into().unwrap()))
        .collect();

    // Verify double-null termination: last two u16s must be 0
    assert!(u16_units.len() >= 2);
    assert_eq!(u16_units[u16_units.len() - 1], 0);
    assert_eq!(u16_units[u16_units.len() - 2], 0);

    // Use carrick-nt-abi's find_environment_variable to query
    let var1_name: Vec<u16> = "var1".encode_utf16().collect();
    let val1 = carrick_nt_abi::find_environment_variable(&u16_units, &var1_name);
    assert!(val1.is_some());
    let expected_val1: Vec<u16> = "VALUE1".encode_utf16().collect();
    assert_eq!(val1.unwrap(), &expected_val1[..]);

    let key_two_name: Vec<u16> = "Key_Two".encode_utf16().collect();
    let val2 = carrick_nt_abi::find_environment_variable(&u16_units, &key_two_name);
    assert!(val2.is_some());
    let expected_val2: Vec<u16> = "VALUE_TWO".encode_utf16().collect();
    assert_eq!(val2.unwrap(), &expected_val2[..]);

    let empty_name: Vec<u16> = "EMPTY".encode_utf16().collect();
    let val_empty = carrick_nt_abi::find_environment_variable(&u16_units, &empty_name);
    assert!(val_empty.is_some());
    assert_eq!(val_empty.unwrap(), &[]);

    let missing_name: Vec<u16> = "NONEXISTENT".encode_utf16().collect();
    assert!(carrick_nt_abi::find_environment_variable(&u16_units, &missing_name).is_none());
}

#[test]
fn test_encoder_alignment_across_arbitrary_string_lengths() {
    // Test with varying lengths to ensure 8-byte alignment regardless of string lengths
    for cmd in &[
        "a", "ab", "abc", "abcd", "abcde", "abcdef", "abcdefg", "12345678",
    ] {
        for path in &["x", "xy", "xyz", "C:\\foo.exe", "C:\\a\\b\\c\\d.exe"] {
            let config = ProcessMemoryConfig {
                image_path: path,
                command_line: cmd,
                environment: &[("K", "V")],
                ..ProcessMemoryConfig::default()
            };
            let image = ProcessMemoryImage::build(&config);
            let header = image.parameters_header();

            assert_eq!(
                header.image_path_name.buffer.as_u64() % 8,
                0,
                "ImagePath buffer unaligned"
            );
            assert_eq!(
                header.command_line.buffer.as_u64() % 8,
                0,
                "CommandLine buffer unaligned"
            );
            assert_eq!(
                header.environment.as_u64() % 8,
                0,
                "Environment buffer unaligned"
            );

            assert_eq!(image.read_command_line_str(), *cmd);
        }
    }
}
