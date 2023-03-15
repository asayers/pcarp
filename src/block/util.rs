use bytes::*;
use thiserror::Error;

#[derive(Clone, PartialEq, Eq, Debug, Copy)]
pub enum Endianness {
    Big,
    Little,
}

pub(crate) trait FromBytes: Sized {
    fn parse<T: Buf>(buf: T, endianness: Endianness) -> Result<Self, BlockError>;
}

/// A block is corrupt.  We can continue parsing further blocks
#[derive(Debug, Error)]
pub enum BlockError {
    #[error("Not enough bytes")]
    TruncatedBlock,
}

macro_rules! ensure_remaining {
    ($buf:expr, $len:expr) => {
        if $buf.remaining() < $len {
            return Err(BlockError::TruncatedBlock);
        }
    };
}
pub(crate) use ensure_remaining;

pub(crate) fn read_u32<T: Buf>(buf: &mut T, endianness: Endianness) -> u32 {
    match endianness {
        Endianness::Big => buf.get_u32(),
        Endianness::Little => buf.get_u32_le(),
    }
}

pub(crate) fn read_u16<T: Buf>(buf: &mut T, endianness: Endianness) -> u16 {
    match endianness {
        Endianness::Big => buf.get_u16(),
        Endianness::Little => buf.get_u16_le(),
    }
}

pub(crate) fn read_i64<T: Buf>(buf: &mut T, endianness: Endianness) -> i64 {
    match endianness {
        Endianness::Big => buf.get_i64(),
        Endianness::Little => buf.get_i64_le(),
    }
}

pub(crate) fn read_u64<T: Buf>(buf: &mut T, endianness: Endianness) -> u64 {
    match endianness {
        Endianness::Big => buf.get_u64(),
        Endianness::Little => buf.get_u64_le(),
    }
}

pub(crate) fn read_bytes<T: Buf>(buf: &mut T, len: u32) -> Result<Bytes, BlockError> {
    let padding = (4 - len % 4) % 4;
    ensure_remaining!(buf, len as usize + padding as usize);
    let bytes = buf.copy_to_bytes(len as usize);
    buf.advance(padding as usize);
    Ok(bytes)
}

/// A certain number of "units" since the epoch
///
/// The meaning of "unit" is defined by the if_tsresol option in the relevant
/// interface definition block.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Timestamp(pub u64);
pub(crate) fn read_ts<T: Buf>(buf: &mut T, endianness: Endianness) -> Timestamp {
    let hi = read_u32(buf, endianness);
    let lo = read_u32(buf, endianness);
    Timestamp((u64::from(hi) << 32) + u64::from(lo))
}
