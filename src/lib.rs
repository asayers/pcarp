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
extern crate byteorder;
#[macro_use] extern crate log;

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
