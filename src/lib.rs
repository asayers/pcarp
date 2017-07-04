extern crate byteorder;
#[macro_use] extern crate log;

pub mod blocks;
pub mod section;
pub mod types;
pub mod link_type;

use byteorder::{ByteOrder, BigEndian, LittleEndian};
use section::*;
use std::io::{BufRead, BufReader, Read};
use types::*;
use blocks::*;

pub struct Pcapng<R, F> {
    rdr: BufReader<R>,
    endianness: Endianness,
    handle_packet: F,
    current_section: Section,
}

impl<R: Read, F: Fn(&[u8])> Pcapng<R, F> {
    pub fn new(rdr: R, handle_packet: F) -> Pcapng<R, F> {
        Pcapng {
            rdr: BufReader::with_capacity(10_000_000, rdr),
            endianness: Endianness::Big, // arbitrary
            handle_packet: handle_packet,
            current_section: Section::new(),
        }
    }

    fn next_block(&mut self) -> Result<()> {
        if let Some(new_endianness) = peek_for_shb(&mut self.rdr)? {
            debug!("SHB coming up, setting endianness to {:?}", new_endianness);
            self.endianness = new_endianness;
        }
        match self.endianness {
            Endianness::Big    => self.read_block::<BigEndian>(),
            Endianness::Little => self.read_block::<LittleEndian>(),
        }
    }

    fn read_block<B: ByteOrder>(&mut self) -> Result<()> {
        let block_length = {
            let buf = self.rdr.fill_buf().unwrap();
            if buf.len() < 8 { return Err(Error::NotEnoughBytes); }
            let block_type   = B::read_u32(&buf[..4]);
            let block_length = B::read_u32(&buf[4..8]) as usize;
            if buf.len() < 12 + block_length { return Err(Error::NotEnoughBytes); }
            debug!("Got block, type {:x}, len {}", block_type, block_length);
            let body = &buf[8..block_length - 4];
            let block_length_2 = B::read_u32(&buf[block_length - 4..block_length]) as usize;
            assert_eq!(block_length, block_length_2, "Block's start and end lengths don't match");
            let block = Block::parse::<B>(block_type, body)?;
            let pkt = self.current_section.handle_block(block);
            block_length
        };
        self.rdr.consume(block_length);
        Ok(())
    }
}

/// First we just need to check if it's an SHB, and set the endinanness if it is. This function
/// doesn't consume anything from the buffer, it just peeks.
fn peek_for_shb<R: BufRead>(rdr: &mut R) -> Result<Option<Endianness>> {
    let buf = rdr.fill_buf().unwrap();
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
