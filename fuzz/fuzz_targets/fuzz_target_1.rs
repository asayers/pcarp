#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let cap = pcarp::Capture::new(std::io::Cursor::new(data));
    for _ in cap {}
});
