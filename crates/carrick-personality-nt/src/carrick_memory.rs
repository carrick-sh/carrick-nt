//! Carrick kernel user-memory adapter seam for carrick-personality-nt.
//!
//! Provides the adapter binding between the NT personality `UserMemory` port trait
//! and Carrick kernel's personality-facing user copy-in / copy-out primitives (carrick#209).
//!
//! Real implementation will bridge Carrick's personality-facing user copy seam once
//! carrick PR #209 lands upstream.

/// Adapter implementing `UserMemory` over Carrick kernel copy primitives.
///
/// This adapter will bridge Carrick's personality-facing user copy seam (carrick#209)
/// into the `UserMemory` port trait consumed by `NtDispatcher`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CarrickUserMemory;

impl CarrickUserMemory {
    /// Creates a new `CarrickUserMemory` adapter.
    pub const fn new() -> Self {
        Self
    }
}
