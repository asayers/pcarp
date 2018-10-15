/*!

From https://www.tcpdump.org/pcap/pcap.html:

> The problem of exchanging packet traces becomes more and more critical every day; unfortunately, no
> standard solutions exist for this task right now. One of the most accepted packet interchange
> formats is the one defined by libpcap, which is rather old and is lacking in functionality for more
> modern applications particularly from the extensibility point of view.
>
> This document proposes a new format for recording packet traces. The following goals are being
> pursued:
>
> * Extensibility: It should be possible to add new standard capabilities to the file format over
>   time, and third parties should be able to enrich the information embedded in the file with
>   proprietary extensions, with tools unaware of newer extensions being able to ignore them.
> * Portability: A capture trace must contain all the information needed to read data independently
>   from network, hardware and operating system of the machine that made the capture.
> * Merge/Append data: It should be possible to add data at the end of a given file, and the
>   resulting file must still be readable.

Copyright (C) The Internet Society (2004). All Rights Reserved.
*/

extern crate buf_redux;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    #[test]
    fn test_dhcp_big() {
        let file = File::open("test_data/dhcp_big_endian.pcapng").unwrap();
        let mut pcap = Pcapng::new(file).unwrap();
        assert!(pcap.next().is_ok(), "failed to parse the SHB");
        assert!(pcap.next().is_ok(), "failed to parse the IDB");
        assert!(pcap.next().is_ok(), "failed to parse the NRB");
        for i in 0..4 {
            assert!(pcap.next().is_ok(), "failed to parse the #{} EPB", i);
        }
    }

    #[test]
    fn test_dhcp_little() {
        let file = File::open("test_data/dhcp_little_endian.pcapng").unwrap();
        let mut pcap = Pcapng::new(file).unwrap();
        assert!(pcap.next().is_ok(), "failed to parse the SHB");
        assert!(pcap.next().is_ok(), "failed to parse the IDB");
        assert!(pcap.next().is_ok(), "failed to parse the NRB");
        for i in 0..4 {
            assert!(pcap.next().is_ok(), "failed to parse the #{} EPB", i);
        }
    }

    #[test]
    fn test_many() {
        let file = File::open("test_data/many_interfaces.pcapng").unwrap();
        let mut pcap = Pcapng::new(file).unwrap();
        {
            let r = pcap.next();
            assert!(r.is_ok(), "failed to parse the SHB: {:?}", r);
        }
        for i in 0..11 {
            let r = pcap.next();
            assert!(r.is_ok(), "failed to parse the #{} IDB: {:?}", i, r);
        }
        {
            let r = pcap.next();
            assert!(r.is_ok(), "failed to parse the NRB: {:?}", r);
        }
        for i in 0..11 {
            let r = pcap.next();
            assert!(r.is_ok(), "failed to parse the #{} ISB: {:?}", i, r);
        }
        for i in 0..64 {
            let r = pcap.next();
            assert!(r.is_ok(), "failed to parse the #{} EPB: {:?}", i, r);
        }
    }
}
