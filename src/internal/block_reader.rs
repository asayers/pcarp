use buf_redux::policy::MinBuffered;
use buf_redux::BufReader;
use byteorder::{BigEndian, LittleEndian};
use error::*;
use internal::*;
use std::io::{BufRead, Read};

pub struct BlockReader<R> {
    rdr: BufReader<R, MinBuffered>,
    endianness: Endianness,
}

const DEFAULT_MIN_BUFFERED: usize = 8 * 1024; // 8KB

impl<R: Read> BlockReader<R> {
    pub fn new(rdr: R) -> Result<BlockReader<R>> {
        Self::with_capacity(rdr, BUF_CAPACITY)
    }

    pub fn with_capacity(rdr: R, cap: usize) -> Result<BlockReader<R>> {
        let mut rdr =
            BufReader::with_capacity(cap, rdr).set_policy(MinBuffered(DEFAULT_MIN_BUFFERED));
        let endianness = peek_for_shb(rdr.fill_buf()?)?.ok_or(Error::DidntStartWithSHB)?;
        Ok(BlockReader {
            rdr,
            endianness,
        })
    }

    pub fn advance<'a>(&'a mut self) -> Result<()> {
        // Look at the length of the _current_ block, to see how much data to discard
        let prev_block_len = match self.endianness {
            Endianness::Big => parse_framed_len::<BigEndian>(self.rdr.buffer()),
            Endianness::Little => parse_framed_len::<LittleEndian>(self.rdr.buffer()),
        }?;
        self.rdr.consume(prev_block_len as usize);

        let buf = self.rdr.fill_buf()?;
        if buf.is_empty() {
            return Err(Error::ZeroBytes);
        }

        // We might have a new section coming up; in which case, change endianness.
        if let Some(endianness) = peek_for_shb(buf)? {
            debug!("Found SHB; setting endianness to {:?}", endianness);
            self.endianness = endianness;
        }
        Ok(())
    }

    pub fn get(&self) -> Result<Block> {
        match self.endianness {
            Endianness::Big => parse_framed_block::<BigEndian>(self.rdr.buffer()),
            Endianness::Little => parse_framed_block::<LittleEndian>(self.rdr.buffer()),
        }
    }
}

/// First we just need to check if it's an SHB, and set the endinanness if it is. This function
/// doesn't consume anything from the buffer, it just peeks.
fn peek_for_shb(buf: &[u8]) -> Result<Option<Endianness>> {
    require_bytes(buf, 4)?;
    let block_type = &buf[..4];
    if block_type != [0x0A, 0x0D, 0x0D, 0x0A] {
        return Ok(None);
    }
    require_bytes(buf, 12)?;
    let endianness = Endianness::parse_from_magic(&buf[8..12])?;
    Ok(Some(endianness))
}
