pub mod blocks;
pub mod section;
pub mod types;
pub mod link_type;

use section::*;
use std::io::{BufRead, BufReader, Read};
use types::*;

pub struct Pcapng<R, F> {
    rdr: BufReader<R>,
    handle_packet: F,
    section: Section,  // The current section
}

impl<R: Read, F: Fn(Packet)> Pcapng<R, F> {
    pub fn new(rdr: R, handle_packet: F) -> Result<Pcapng<R, F>> {
        let mut rdr = BufReader::with_capacity(BUF_CAPACITY, rdr);
        let endianness = peek_for_shb(rdr.fill_buf().unwrap())?.unwrap();
        Ok(Pcapng {
            rdr: rdr,
            handle_packet: handle_packet,
            section: Section::new(endianness),
        })
    }

    pub fn next_block(&mut self) -> Result<()> {
        let consumed_length = {
            let buf = self.rdr.fill_buf().unwrap();
            if let Some(endianness) = peek_for_shb(buf)? {
                debug!("Found SHB; starting new section with endianness {:?}", endianness);
                self.section = Section::new(endianness);
            }
            let (consumed_length, pkt) = self.section.handle_block(buf)?;
            if let Some(pkt) = pkt { (self.handle_packet)(pkt); }
            consumed_length
        };
        self.rdr.consume(consumed_length);
        Ok(())
    }
}

/// First we just need to check if it's an SHB, and set the endinanness if it is. This function
/// doesn't consume anything from the buffer, it just peeks.
fn peek_for_shb(buf: &[u8]) -> Result<Option<Endianness>> {
    if buf.len() < 4 { return Err(Error::NotEnoughBytes); }
    let block_type = &buf[..4];
    if block_type != &[0x0A, 0x0D, 0x0D, 0x0A] { return Ok(None); }
    if buf.len() < 12 { return Err(Error::NotEnoughBytes); }
    let mut magic = [0;4]; magic.copy_from_slice(&buf[8..12]);
    if magic == [0x1A, 0x2B, 0x3C, 0x4D] {
        Ok(Some(Endianness::Big))
    } else if magic == [0x4D, 0x3C, 0x2B, 0x1A] {
        Ok(Some(Endianness::Little))
    } else {
        Err(Error::DidntUnderstandMagicNumber(magic))
    }
}
