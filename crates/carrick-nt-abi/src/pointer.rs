//! Guest memory pointer and length typed domain primitives.
//!
//! Follows Carrick's typed-domain rules: no bare `u64` across semantic boundaries.

use core::fmt;
use core::marker::PhantomData;

/// Guest virtual address typed newtype.
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct GuestVa(pub u64);

impl GuestVa {
    /// Null virtual address.
    pub const NULL: Self = Self(0);

    /// Creates a `GuestVa` from a raw 64-bit address.
    #[inline]
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    /// Returns the raw 64-bit address.
    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Returns `true` if this address is null (0).
    #[inline]
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }

    /// Returns an offset virtual address, wrapping on overflow.
    #[inline]
    pub const fn wrapping_add(self, offset: u64) -> Self {
        Self(self.0.wrapping_add(offset))
    }

    /// Checked addition for guest address arithmetic.
    #[inline]
    pub const fn checked_add(self, offset: u64) -> Option<Self> {
        match self.0.checked_add(offset) {
            Some(val) => Some(Self(val)),
            None => None,
        }
    }
}

impl fmt::Debug for GuestVa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GuestVa(0x{:016X})", self.0)
    }
}

impl fmt::Display for GuestVa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:016X}", self.0)
    }
}

impl From<u64> for GuestVa {
    #[inline]
    fn from(val: u64) -> Self {
        Self(val)
    }
}

impl From<GuestVa> for u64 {
    #[inline]
    fn from(va: GuestVa) -> Self {
        va.0
    }
}

/// Typed guest pointer wrapping a `GuestVa` and associated target type `T`.
#[repr(transparent)]
pub struct GuestPtr<T> {
    addr: GuestVa,
    _marker: PhantomData<*const T>,
}

impl<T> Copy for GuestPtr<T> {}

impl<T> Clone for GuestPtr<T> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> PartialEq for GuestPtr<T> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr
    }
}

impl<T> Eq for GuestPtr<T> {}

impl<T> PartialOrd for GuestPtr<T> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for GuestPtr<T> {
    #[inline]
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.addr.cmp(&other.addr)
    }
}

impl<T> Default for GuestPtr<T> {
    #[inline]
    fn default() -> Self {
        Self::null()
    }
}

impl<T> GuestPtr<T> {
    /// Null pointer.
    pub const NULL: Self = Self {
        addr: GuestVa::NULL,
        _marker: PhantomData,
    };

    /// Creates a typed `GuestPtr` from a `GuestVa`.
    #[inline]
    pub const fn from_va(addr: GuestVa) -> Self {
        Self {
            addr,
            _marker: PhantomData,
        }
    }

    /// Creates a typed `GuestPtr` from a raw `u64`.
    #[inline]
    pub const fn from_raw(addr: u64) -> Self {
        Self {
            addr: GuestVa::new(addr),
            _marker: PhantomData,
        }
    }

    /// Creates a null `GuestPtr`.
    #[inline]
    pub const fn null() -> Self {
        Self::NULL
    }

    /// Returns the underlying `GuestVa`.
    #[inline]
    pub const fn va(self) -> GuestVa {
        self.addr
    }

    /// Returns the raw 64-bit integer address.
    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.addr.as_u64()
    }

    /// Returns `true` if this pointer is null.
    #[inline]
    pub const fn is_null(self) -> bool {
        self.addr.is_null()
    }

    /// Casts this pointer to a different target type.
    #[inline]
    pub const fn cast<U>(self) -> GuestPtr<U> {
        GuestPtr {
            addr: self.addr,
            _marker: PhantomData,
        }
    }
}

impl<T> fmt::Debug for GuestPtr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GuestPtr<{}>({})",
            core::any::type_name::<T>(),
            self.addr
        )
    }
}

/// Typed buffer or string length (32-bit, matching Windows `ULONG` / `DWORD` lengths).
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct UserLength(pub u32);

impl UserLength {
    /// Zero length.
    pub const ZERO: Self = Self(0);

    /// Creates a `UserLength` from a raw `u32`.
    #[inline]
    pub const fn new(len: u32) -> Self {
        Self(len)
    }

    /// Returns the length as `u32`.
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Returns the length as `usize`.
    #[inline]
    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl fmt::Debug for UserLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UserLength({})", self.0)
    }
}

/// Typed 64-bit byte count (such as transferred bytes in `IO_STATUS_BLOCK`).
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ByteCount(pub u64);

impl ByteCount {
    /// Zero byte count.
    pub const ZERO: Self = Self(0);

    /// Creates a `ByteCount` from a raw `u64`.
    #[inline]
    pub const fn new(count: u64) -> Self {
        Self(count)
    }

    /// Returns the count as `u64`.
    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Returns the count as `usize`.
    #[inline]
    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl fmt::Debug for ByteCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ByteCount({})", self.0)
    }
}
