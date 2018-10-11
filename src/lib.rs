/*!
The problem of exchanging packet traces becomes more and more critical every day; unfortunately, no
standard solutions exist for this task right now. One of the most accepted packet interchange
formats is the one defined by libpcap, which is rather old and is lacking in functionality for more
modern applications particularly from the extensibility point of view.

This document proposes a new format for recording packet traces. The following goals are being
pursued:

* Extensibility: It should be possible to add new standard capabilities to the file format over
  time, and third parties should be able to enrich the information embedded in the file with
  proprietary extensions, with tools unaware of newer extensions being able to ignore them.
* Portability: A capture trace must contain all the information needed to read data independently
  from network, hardware and operating system of the machine that made the capture.
* Merge/Append data: It should be possible to add data at the end of a given file, and the
  resulting file must still be readable.
*/

extern crate byteorder;
#[macro_use]
extern crate log;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate num_derive;
extern crate num_traits;

mod error;
pub mod internal;
mod link_type;
mod packet;

pub use error::*;
pub use internal::InterfaceDescription;
use internal::*;
pub use link_type::*;
pub use packet::*;
use std::io::Read;

pub struct Pcapng<R> {
    block_reader: BlockReader<R>,
    section: Section,
}

impl<R: Read> Pcapng<R> {
    pub fn new(rdr: R) -> Result<Pcapng<R>> {
        Ok(Pcapng {
            block_reader: BlockReader::new(rdr)?,
            section: Section::new(),
        })
    }

    pub fn next<'a>(&'a mut self) -> Result<Option<Packet<'a>>> {
        let block = self.block_reader.next_block()?;
        Ok(self.section.handle_block(block))
    }
}
