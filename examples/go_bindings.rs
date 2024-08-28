

fn main() {
    // This function is required as an entry point
    // You can leave it empty if you're only using this file for FFI
}






// lib.rs

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

#[no_mangle]
pub extern "C" fn greet(name: *const c_char) -> *mut c_char {
    let name = unsafe { CStr::from_ptr(name).to_str().unwrap() };
    let greeting = format!("Hello, {}!", name);
    let c_greeting = std::ffi::CString::new(greeting).unwrap();
    c_greeting.into_raw()
}

#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    unsafe {
        if s.is_null() { return }
        let _ = CString::from_raw(s);
    };
}