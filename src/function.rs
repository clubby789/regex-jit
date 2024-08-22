use std::ffi::c_void;

pub struct RegexFunction(*mut c_void, usize);

impl RegexFunction {
    /// Construct a new [`RegexFunction`] from a pointer to executable memory
    /// SAFETY: The pointer must point to valid code, and not aliased by any mutable references.
    pub unsafe fn new(ptr: *mut c_void, size: usize) -> Self {
        Self(ptr, size)
    }

    pub fn matches(&self, text: &str) -> bool {
        type FnPointer = extern "C" fn(*const u8, usize) -> bool;
        let func: FnPointer = unsafe { std::mem::transmute(self.0) };
        func(text.as_ptr(), text.len())
    }
}

impl Drop for RegexFunction {
    fn drop(&mut self) {
        unsafe {
            assert!(
                libc::munmap(self.0, self.1) == 0,
                "failed to munmap regex code"
            )
        }
    }
}
