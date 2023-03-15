use crate::block::frame::*;
use crate::block::*;
use crate::{Error, Result};
use bytes::{Buf, Bytes, BytesMut};
use std::io::Read;
use std::io::{Seek, SeekFrom};

/// An iterator that reads blocks from a pcap
pub struct BlockReader<R> {
    rdr: R,
    buf: Bytes,
    /// Whether an unrecoverable error has occurred
    dead: bool,
    /// Endianness of the current section
    endianness: Endianness,
}

impl<R> BlockReader<R> {
    pub(crate) const BUF_CAPACITY: usize = 8 * 1024; // 8KiB

    /// Create a new `BlockReader`.
    pub fn new(rdr: R) -> BlockReader<R> {
        BlockReader {
            rdr,
            buf: Bytes::new(),
            dead: false,
            endianness: Endianness::Little, // arbitrary
        }
    }

    /// Rewind to the beginning of the pcapng file
    pub fn rewind(&mut self) -> std::io::Result<()>
    where
        R: Seek,
    {
        self.rdr.seek(SeekFrom::Start(0))?;
        self.buf = Bytes::new();
        self.dead = false;
        self.endianness = Endianness::Little;
        Ok(())
    }
}

impl<R: Read> Iterator for BlockReader<R> {
    type Item = Result<Block>;
    fn next(&mut self) -> Option<Self::Item> {
        self.try_next().transpose()
    }
}

impl<R: Read> BlockReader<R> {
    /// In the event of an IO error, no state is modified.  It should be
    /// safe to just try again.
    fn fill_buf(&mut self) -> std::io::Result<usize> {
        // This is evil because it relies on R's read() being correctly
        // implemented for safety.
        let n_leftover = self.buf.len();
        let mut new_buf = BytesMut::zeroed(Self::BUF_CAPACITY + n_leftover);
        new_buf[..n_leftover].copy_from_slice(&self.buf);
        let n_read = self.rdr.read(&mut new_buf[n_leftover..])?;
        new_buf.truncate(n_leftover + n_read);
        self.buf = new_buf.freeze();
        Ok(n_read)
    }

    // It's faster than fill_buf().  However, it's evil because it relies on
    // `R::read()` being sanely implemented for safety.  The `Read` docs
    // explicitly say not to do this.
    //
    // Concretely, if `R::read()` peeks at the buffer, it will see
    // uninitialized memory.  If `R::read()` claims to have written more
    // bytes than it actually did, we'll try to parse some uninitialized
    // memory later.  In either case, it's UB.
    //
    // fn fill_buf_evil(&mut self) -> std::io::Result<usize> {
    //     use bytes::BufMut;
    //     self.buf.reserve(Self::BUF_CAPACITY / 2);
    //     let dst = self.buf.chunk_mut();
    //     let dst = unsafe { &mut *(dst as *mut _ as *mut [std::mem::MaybeUninit<u8>] as *mut [u8]) };
    //     let n_read = self.rdr.read(dst)?;
    //     unsafe {
    //         self.buf.advance_mut(n_read);
    //     }
    //     Ok(n_read)
    // }

    /// Get the next block.
    pub(crate) fn try_next(&mut self) -> Result<Option<Block>> {
        if self.dead {
            return Ok(None);
        }
        loop {
            match parse_frame(self.buf.chunk(), &mut self.endianness) {
                Ok(Some((block_type, data_len))) => {
                    self.buf.advance(8);
                    let block_data = self.buf.copy_to_bytes(data_len);
                    self.buf.advance(4);
                    trace!("Saw a complete {block_type:?} block, len {data_len}");
                    match Block::parse(block_type, block_data, self.endianness) {
                        Ok(block) => {
                            trace!("Parsed block as {block:?}");
                            return Ok(Some(block));
                        }
                        Err(e) => return Err(Error::Block(block_type, e)),
                    }
                }
                Err(e) => {
                    // Framing errors are unrecoverable
                    self.dead = true;
                    return Err(e.into());
                }
                Ok(None) => {
                    let n_read = self.fill_buf()?;
                    debug!("Read {n_read} bytes");
                    if n_read == 0 {
                        return Ok(None);
                    } else {
                        continue;
                    }
                }
            }
        }
    }
}
