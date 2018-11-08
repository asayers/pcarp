/*!
pcarp is pure-Rust library for reading pcap-ng files.

* _Correct_: Produces the same results as `tshark` for all the pcapng files I
  could scrape from the [Wireshark wiki][1].
* _Fast_: About 4x faster than `libpcap`.
* _Flexible_: Takes anything which implements `Read` as input.  Are your pcaps
  compressed?  No problem, just wrap them in a [`GzDecoder`][2].

[1]: https://wiki.wireshark.org/SampleCaptures
[2]: https://docs.rs/flate2/1/flate2/read/struct.GzDecoder.html
*/

extern crate buf_redux;
extern crate byteorder;
#[macro_use]
extern crate log;
#[macro_use]
extern crate failure;
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
    /// Create a new `Pcapng`.
    pub fn new(rdr: R) -> Result<Pcapng<R>> {
        Ok(Pcapng {
            block_reader: BlockReader::new(rdr)?,
            section: Section::new(),
        })
    }

    pub fn advance(&mut self) -> Result<()> {
        self.block_reader.advance()?;
        let block = self.block_reader.get()?;
        self.section.handle_block(&block);
        Ok(())
    }

    pub fn get<'a>(&'a self) -> Result<Option<Packet<'a>>> {
        let block = self.block_reader.get()?;
        Ok(self.section.block_to_packet(block))
    }

    /// Get the next packet
    pub fn next<'a, 'b>(&'a mut self) -> Result<Packet<'b>> where 'a: 'b {
        loop {
            self.advance()?;
            if self.get()?.is_some() { break; }
        }
        Ok(self.get()?.unwrap())
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
