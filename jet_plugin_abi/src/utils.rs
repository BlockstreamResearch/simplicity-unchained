/// Borrowed byte string.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Bytes {
    pub ptr: *const u8,
    pub len: usize,
}

impl Bytes {
    pub const fn new(bytes: &'static [u8]) -> Self {
        Self {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
        }
    }

    /// # Safety
    ///
    /// `ptr` must be valid for reads of `len` bytes for the whole of `'a`.
    pub unsafe fn as_slice<'a>(&self) -> &'a [u8] {
        if self.len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
        }
    }
}
