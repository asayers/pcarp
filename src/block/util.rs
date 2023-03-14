use crate::{Error, Result};
use byteorder::{BigEndian, ByteOrder, LittleEndian};

#[derive(Clone, PartialEq, Eq, Debug, Copy)]
pub enum Endianness {
    Big,
    Little,
}

impl Endianness {
    pub fn parse_from_magic(buf: &[u8]) -> Result<Self> {
        let magic = &buf[0..4];
        match magic {
            [0x1A, 0x2B, 0x3C, 0x4D] => Ok(Endianness::Big),
            [0x4D, 0x3C, 0x2B, 0x1A] => Ok(Endianness::Little),
            _ => {
                let mut unknown_magic = [0; 4];
                unknown_magic.copy_from_slice(magic);
                Err(Error::DidntUnderstandMagicNumber(unknown_magic))
            }
        }
    }
}

pub trait KnownByteOrder {
    fn endianness() -> Endianness;
}

impl KnownByteOrder for BigEndian {
    fn endianness() -> Endianness {
        Endianness::Big
    }
}

impl KnownByteOrder for LittleEndian {
    fn endianness() -> Endianness {
        Endianness::Little
    }
}

pub trait FromBytes<'a>: Sized {
    fn parse<B: ByteOrder + KnownByteOrder>(buf: &'a [u8]) -> Result<Self>;
}

pub fn require_bytes(buf: &[u8], len: usize) -> Result<()> {
    if buf.len() < len {
        Err(Error::NotEnoughBytes {
            expected: len,
            actual: buf.len(),
        })
    } else {
        Ok(())
    }
}
