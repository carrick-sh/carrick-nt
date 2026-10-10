//! High-level PE image loader and mapping planner.
//!
//! Conforms strictly to Microsoft PE and COFF Specification (Rev 11.0).

use crate::error::PeError;
use crate::headers::PeHeaders;
use crate::imports::{parse_and_resolve_imports, ExportProvider, StubExportProvider};
use crate::plan::{
    FileRange, MappedRegion, MappingPlan, PageProtection, VirtualAddress, VirtualRange,
};
use crate::relocations::parse_and_compute_relocations;
use crate::tls::parse_tls_directory;
use alloc::string::String;
use alloc::vec::Vec;

/// Clean-room PE/COFF loader that inspects an image and constructs a typed MappingPlan.
pub struct PeLoader<P = StubExportProvider> {
    export_provider: P,
    override_base: Option<VirtualAddress>,
}

impl Default for PeLoader<StubExportProvider> {
    fn default() -> Self {
        Self::new(StubExportProvider::default())
    }
}

impl<P: ExportProvider> PeLoader<P> {
    /// Creates a new PeLoader with the given pluggable export provider.
    pub fn new(provider: P) -> Self {
        Self {
            export_provider: provider,
            override_base: None,
        }
    }

    /// Sets an explicit target base address for relocation (simulating ASLR or dynamic base).
    pub fn with_base(mut self, base: VirtualAddress) -> Self {
        self.override_base = Some(base);
        self
    }

    /// Parses the PE binary, resolves its imports, computes base relocations,
    /// and generates a complete, typed MappingPlan.
    pub fn load(&self, file_bytes: &[u8]) -> Result<MappingPlan, PeError> {
        let headers = PeHeaders::parse(file_bytes)?;

        let actual_base = self
            .override_base
            .unwrap_or_else(|| VirtualAddress::new(headers.optional.image_base));

        // 1. Plan memory regions
        let mut regions = Vec::with_capacity(1 + headers.sections.len());

        // Headers region: mapped at actual_base, read-only
        let headers_size = headers.optional.size_of_headers as u64;
        let headers_range =
            VirtualRange::from_start_size(actual_base, headers_size).map_err(PeError::Mapping)?;
        let headers_file_range = FileRange::new(0, headers_size.min(file_bytes.len() as u64));

        regions.push(MappedRegion {
            name: String::from("headers"),
            virtual_range: headers_range,
            file_range: Some(headers_file_range),
            zero_fill_len: 0,
            protection: PageProtection::ReadOnly,
        });

        // Map each section
        for sec in &headers.sections {
            let sec_va = actual_base.checked_add(sec.virtual_address as u64).ok_or(
                PeError::OutOfBoundsRva {
                    rva: sec.virtual_address,
                    context: "Section VA overflow",
                },
            )?;

            let virtual_span = sec.aligned_virtual_span(headers.optional.section_alignment) as u64;
            let virtual_range =
                VirtualRange::from_start_size(sec_va, virtual_span).map_err(PeError::Mapping)?;

            let file_range = if sec.size_of_raw_data > 0 {
                Some(FileRange::new(
                    sec.pointer_to_raw_data as u64,
                    sec.size_of_raw_data as u64,
                ))
            } else {
                None
            };

            let zero_fill_len = sec.zero_fill_len() as u64;
            let protection = PageProtection::from_characteristics(sec.characteristics);

            regions.push(MappedRegion {
                name: sec.name.clone(),
                virtual_range,
                file_range,
                zero_fill_len,
                protection,
            });
        }

        // 2. Base relocations
        let relocations = parse_and_compute_relocations(&headers, file_bytes, actual_base)?;

        // 3. Resolve imports
        let import_bindings =
            parse_and_resolve_imports(&headers, file_bytes, actual_base, &self.export_provider)?;

        // 4. Parse TLS
        let tls = parse_tls_directory(&headers, file_bytes)?;

        // 5. Entry point address
        let entry_point = if headers.optional.address_of_entry_point != 0 {
            actual_base
                .checked_add(headers.optional.address_of_entry_point as u64)
                .ok_or(PeError::OutOfBoundsRva {
                    rva: headers.optional.address_of_entry_point,
                    context: "AddressOfEntryPoint overflow",
                })?
        } else {
            actual_base
        };

        Ok(MappingPlan {
            image_base: actual_base,
            preferred_image_base: VirtualAddress::new(headers.optional.image_base),
            entry_point,
            total_virtual_size: headers.optional.size_of_image as u64,
            regions,
            import_bindings,
            relocations,
            tls,
        })
    }
}
