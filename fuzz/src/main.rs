extern crate afl;
extern crate pcarp;

use afl::fuzz;
use std::io::Cursor;

fn main() {
    fuzz!(|data: &[u8]| {
        let cap = pcarp::Capture::new(Cursor::new(data));
        match cap {
            Ok(mut cap) => {
                while let Some(pkt) = cap.next() {
                    match pkt {
                        Ok(_) => println!("ok"),
                        Err(e) => eprintln!("{}", e),
                    }
                }
            }
            Err(e) => eprintln!("{}", e),
        }
    });
}
