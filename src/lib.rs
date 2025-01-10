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

/// Parse a DEX file and return a DEX context
///
/// TODO: change for pathbuf
pub fn parse_dex(filepath: String) -> DexContext {
    let c_str = CString::new(filepath).unwrap();
    let c_world = c_str.as_ptr();
    unsafe {
        DexContext(shuriken::parse_dex(c_world))
    }
}

