//! Test loading the real clean-room hello_console.exe fixture.
//!
//! Conforms to Microsoft PE and COFF Specification (Rev 11.0).

mod common;

use carrick_pe_loader::imports::{ImportSymbol, StubExportProvider};
use carrick_pe_loader::mapper::PeLoader;
use carrick_pe_loader::plan::{PageProtection, VirtualAddress};
use common::{create_pe_with_relocations, get_hello_console_bytes};

#[test]
fn test_load_real_hello_console_fixture() {
    let bytes = get_hello_console_bytes();

    let mut provider = StubExportProvider::new();
    let exit_process_va = VirtualAddress::new(0x0000_7FFF_0001_0000);
    let get_std_handle_va = VirtualAddress::new(0x0000_7FFF_0001_1000);
    let write_file_va = VirtualAddress::new(0x0000_7FFF_0001_2000);

    provider.add_symbol("kernel32.dll", "ExitProcess", exit_process_va);
    provider.add_symbol("kernel32.dll", "GetStdHandle", get_std_handle_va);
    provider.add_symbol("kernel32.dll", "WriteFile", write_file_va);

    let loader = PeLoader::new(provider);
    let plan = loader
        .load(&bytes)
        .expect("failed to load hello_console.exe");

    // 1. Verify Image Base and Sizing
    assert_eq!(plan.preferred_image_base.as_u64(), 0x140000000);
    assert_eq!(plan.image_base, plan.preferred_image_base);
    assert!(plan.total_virtual_size > 0);
    assert_eq!(plan.total_virtual_size % 4096, 0);

    // 2. Verify Entry Point
    assert!(plan.entry_point > plan.image_base);
    assert!(plan.entry_point.as_u64() < plan.image_base.as_u64() + plan.total_virtual_size);

    // 3. Verify Mapped Regions
    let headers_region = plan
        .find_region_by_name("headers")
        .expect("missing headers region");
    assert_eq!(headers_region.protection, PageProtection::ReadOnly);
    assert_eq!(headers_region.virtual_range.start, plan.image_base);

    let text_sec = plan.find_region_by_name(".text").expect("missing .text");
    assert_eq!(text_sec.protection, PageProtection::ReadExecute);

    let rdata_sec = plan.find_region_by_name(".rdata").expect("missing .rdata");
    assert_eq!(rdata_sec.protection, PageProtection::ReadOnly);

    let pdata_sec = plan.find_region_by_name(".pdata").expect("missing .pdata");
    assert_eq!(pdata_sec.protection, PageProtection::ReadOnly);

    // 4. Verify Import Bindings
    assert_eq!(plan.import_bindings.len(), 3);
    for binding in &plan.import_bindings {
        assert_eq!(binding.dll_name.to_ascii_lowercase(), "kernel32.dll");
        match &binding.symbol {
            ImportSymbol::Named(name) => match name.as_str() {
                "ExitProcess" => assert_eq!(binding.resolved_va, exit_process_va),
                "GetStdHandle" => assert_eq!(binding.resolved_va, get_std_handle_va),
                "WriteFile" => assert_eq!(binding.resolved_va, write_file_va),
                other => panic!("Unexpected symbol: {other}"),
            },
            ImportSymbol::Ordinal(ord) => panic!("Unexpected ordinal: #{ord}"),
        }
        assert!(binding.iat_rva > 0);
        assert_eq!(
            binding.iat_va.as_u64(),
            plan.image_base.as_u64() + binding.iat_rva as u64
        );
    }

    // 5. Test Buffer Mapping Simulation
    let mut guest_memory = vec![0u8; plan.total_virtual_size as usize];
    plan.apply_to_buffer(&bytes, &mut guest_memory)
        .expect("apply_to_buffer failed");

    // Verify IAT entries written in guest memory buffer
    for binding in &plan.import_bindings {
        let iat_off = binding.iat_rva as usize;
        let written_va = u64::from_le_bytes(guest_memory[iat_off..iat_off + 8].try_into().unwrap());
        assert_eq!(written_va, binding.resolved_va.as_u64());
    }
}

#[test]
fn test_rebase_and_relocate_image() {
    let base_bytes = get_hello_console_bytes();

    // Create binary with DIR64 relocation at .rdata page 0x2000, offset 0x20
    let reloc_page = 0x2000u32;
    let reloc_offset = 0x20u16;
    let bytes = create_pe_with_relocations(&base_bytes, reloc_page, &[(10, reloc_offset)]);

    let mut provider = StubExportProvider::new();
    provider.add_symbol(
        "kernel32.dll",
        "ExitProcess",
        VirtualAddress::new(0x7fff_0001_0000),
    );
    provider.add_symbol(
        "kernel32.dll",
        "GetStdHandle",
        VirtualAddress::new(0x7fff_0001_1000),
    );
    provider.add_symbol(
        "kernel32.dll",
        "WriteFile",
        VirtualAddress::new(0x7fff_0001_2000),
    );

    // Relocate to an alternate base address (e.g. ASLR target)
    let alternate_base = VirtualAddress::new(0x0000_7FF6_2000_0000);
    let loader = PeLoader::new(provider).with_base(alternate_base);
    let plan = loader
        .load(&bytes)
        .expect("failed to load with alternate base");

    assert_eq!(plan.image_base, alternate_base);
    let expected_delta = alternate_base.as_u64() as i64 - plan.preferred_image_base.as_u64() as i64;

    assert_eq!(plan.relocations.len(), 1, "expected 1 base relocation");
    let reloc = &plan.relocations[0];
    assert_eq!(reloc.target_rva, reloc_page + reloc_offset as u32);
    assert_eq!(reloc.delta, expected_delta);
    assert_eq!(
        reloc.relocated_value,
        reloc.original_value.wrapping_add(expected_delta as u64)
    );
    assert_eq!(
        reloc.target_va.as_u64(),
        alternate_base.as_u64() + reloc.target_rva as u64
    );

    // Apply to memory buffer and verify relocated pointer values
    let mut guest_memory = vec![0u8; plan.total_virtual_size as usize];
    plan.apply_to_buffer(&bytes, &mut guest_memory)
        .expect("apply_to_buffer failed for relocated image");

    let off = reloc.target_rva as usize;
    let mem_val = u64::from_le_bytes(guest_memory[off..off + 8].try_into().unwrap());
    assert_eq!(mem_val, reloc.relocated_value);
}
