use buf_redux::policy::MinBuffered;
use buf_redux::BufReader;
use byteorder::{BigEndian, LittleEndian};
use error::*;
use internal::*;
use std::io::{BufRead, Read};

pub struct BlockReader<R> {
    rdr: BufReader<R, MinBuffered>,
    endianness: Endianness,
    consumed: usize,
}

const DEFUALT_MIN_BUFFERED: usize = 8 * 1024; // 8KB

impl<R: Read> BlockReader<R> {
    pub fn new(rdr: R) -> Result<BlockReader<R>> {
        Self::with_capacity(rdr, BUF_CAPACITY)
    }

    pub fn with_capacity(rdr: R, cap: usize) -> Result<BlockReader<R>> {
        let mut rdr =
            BufReader::with_capacity(cap, rdr).set_policy(MinBuffered(DEFUALT_MIN_BUFFERED));
        let endianness = peek_for_shb(rdr.fill_buf()?)?.ok_or(Error::DidntStartWithSHB)?;
        Ok(BlockReader {
            rdr: rdr,
            endianness: endianness,
            consumed: 0,
        })
    }

    pub fn next_block<'a>(&'a mut self) -> Result<Block<'a>> {
        self.rdr.consume(self.consumed);
        self.consumed = 0;
        let buf = self.rdr.fill_buf()?;
        if buf.len() == 0 {
            return Err(Error::ZeroBytes);
        }
        if let Some(endianness) = peek_for_shb(buf)? {
            debug!("Found SHB; setting endianness to {:?}", endianness);
            self.endianness = endianness;
        }
        let frame = match self.endianness {
            Endianness::Big => FramedBlock::parse::<BigEndian>(buf),
            Endianness::Little => FramedBlock::parse::<LittleEndian>(buf),
        }?;
        self.consumed = frame.len;
        Ok(frame.block)
    }
}

/// First we just need to check if it's an SHB, and set the endinanness if it is. This function
/// doesn't consume anything from the buffer, it just peeks.
fn peek_for_shb(buf: &[u8]) -> Result<Option<Endianness>> {
    require_bytes(buf, 4)?;
    let block_type = &buf[..4];
    if block_type != &[0x0A, 0x0D, 0x0D, 0x0A] {
        return Ok(None);
    }
    require_bytes(buf, 12)?;
    let mut magic = [0; 4];
    magic.copy_from_slice(&buf[8..12]);
    if magic == [0x1A, 0x2B, 0x3C, 0x4D] {
        Ok(Some(Endianness::Big))
    } else if magic == [0x4D, 0x3C, 0x2B, 0x1A] {
        Ok(Some(Endianness::Little))
    } else {
        Err(Error::DidntUnderstandMagicNumber(magic))
    }
}
