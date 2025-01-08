#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

use std::ffi::CString;

mod shuriken {
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/shuriken_core.rs"));
}

/// Parse a Dex file
/// TODO: change for pathbuf
pub fn parse_dex(filepath: String) -> shuriken::hDexContext {
    let c_str = CString::new(filepath).unwrap();
    let c_world = c_str.as_ptr();
    unsafe {
        shuriken::parse_dex(c_world)
    }
}
