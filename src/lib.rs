#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

use std::ffi::CString;

mod shuriken {
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/shuriken_core.rs"));
}

/// Type alias for Shuriken's `hDexContext`
pub struct DexContext(shuriken::hDexContext);

impl Drop for DexContext {
    fn drop(&mut self) {
        unsafe {
                shuriken::destroy_dex(self.0);
        }
    }
}

/// Main method from the DEX core API
///
/// Parse a DEX file and return a DEX context
/// TODO: change for pathbuf
pub fn parse_dex(filepath: String) -> DexContext {
    let c_str = CString::new(filepath).unwrap();
    let c_world = c_str.as_ptr();
    unsafe {
        DexContext(shuriken::parse_dex(c_world))
    }
}

/// Get number of strings in the DEX file
pub fn get_number_of_strings(context: DexContext) -> usize {
    unsafe {
        shuriken::get_number_of_strings(context.0)
    }
}
