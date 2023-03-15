use crate::block::*;
use crate::types::Result;
use crate::util::*;
use bytes::{Buf, Bytes, BytesMut};
use std::io::Read;
use std::io::{Seek, SeekFrom};

/// Look for a complete frame at the front of the given buffer
///
/// If the buffer contains a complete frame, this function returns the block
/// type and data length.  If the buffer is empty or contains an incomplete
/// frame, it returns `None`.  If the buffer contains an invalid frame,
/// it returns an error.  Such errors should be treated as fatal.
pub fn parse_frame(buf: &[u8], endianness: &mut Endianness) -> Result<Option<(BlockType, usize)>> {
    // Even a block with an empty body would be 12 bytes long:
    //
    //     type (4) + len (4) + body (0) + len (4) = 12
    //
    // So this check doesn't rule out any blocks.
    //
    // Furthermore, this is enough to cover the first two get_u32()s, and
    // also the magic bytes in the case of an SHB.
    if buf.len() < 12 {
        return Ok(None);
    }

    let read_u32 = |i: usize, endianness: Endianness| -> u32 {
        match endianness {
            Endianness::Big => (&buf[i..i + 4]).get_u32(),
            Endianness::Little => (&buf[i..i + 4]).get_u32_le(),
        }
    };

    let block_type = read_u32(0, *endianness);
    if block_type == 0x0A0D_0D0A {
        // We have a new section coming up.  We may need to change the
        // endianness.
        *endianness = match &buf[8..12] {
            &[0x1A, 0x2B, 0x3C, 0x4D] => Endianness::Big,
            &[0x4D, 0x3C, 0x2B, 0x1A] => Endianness::Little,
            x => return Err(Error::DidntUnderstandMagicNumber(x.try_into().unwrap())),
        };
        trace!("Found SHB; setting endianness to {:?}", *endianness);
    }
    let block_type = BlockType::from(block_type);

    let block_len = read_u32(4, *endianness) as usize;
    if block_len < 12 {
        return Err(Error::BlockLengthMismatch); // TODO
    }
    if buf.len() < block_len {
        return Ok(None);
    }

    let block_len_2 = read_u32(block_len - 4, *endianness) as usize;
    if block_len != block_len_2 {
        return Err(Error::BlockLengthMismatch);
    }

    let data_len = block_len - 12;
    Ok(Some((block_type, data_len)))
}

/// An iterator that reads blocks from a pcap
pub struct BlockReader<R> {
    rdr: BufReader<R, MinBuffered>,
    n_bytes_read: usize,
    finished: bool,
    /// Endianness of the current section
    endianness: Endianness,
    last_block_len: usize,
    current_data: Range<usize>,
}

impl<R: Read> BlockReader<R> {
    pub(crate) const BUF_CAPACITY: usize = 10_000_000;
    pub(crate) const DEFAULT_MIN_BUFFERED: usize = 8 * 1024; // 8KB

    /// Create a new `BlockReader`.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(rdr: R) -> Result<BlockReader<R>> {
        let mut rdr = BufReader::with_capacity(BUF_CAPACITY, rdr)
            .set_policy(MinBuffered(DEFAULT_MIN_BUFFERED));
        let endianness = peek_for_shb(rdr.fill_buf()?)?.ok_or(Error::DidntStartWithSHB)?;
        Ok(BlockReader {
            rdr,
            finished: false,
            endianness,
            last_block_len: 0,
            current_data: 0..0,
        })
    }

    /// Rewind to the beginning of the pcapng file
    pub fn rewind(&mut self) -> Result<()>
    where
        R: Seek,
    {
        self.rdr.seek(SeekFrom::Start(0))?;
        self.finished = false;
        self.endianness = peek_for_shb(self.rdr.fill_buf()?)?.ok_or(Error::DidntStartWithSHB)?;
        self.last_block_len = 0;
        self.current_data = 0..0;
        Ok(())
    }

    pub fn advance(&mut self) -> Result<()> {
        loop {
            // Look at the length of the _last_ block, to see how much data to discard
            self.rdr.consume(self.last_block_len);
            self.n_bytes_read += self.last_block_len;

            // Fill the buffer up - hopefully we'll have enough data for the next block!
            let buf = self.rdr.fill_buf()?;
            if buf.is_empty() {
                self.last_block_len = 0;
                self.finished = true;
                return Ok(());
            }
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
