/*!
Internals.  Not meant for consumption.

Internals are exposed for the sake of interest only.  The usual caveats apply:

* No guarantees about API stability
* The user may need to enforce invariants
* The documentation may be inaccurate

*/

mod block;
mod block_reader;
mod section;

pub use self::block::*;
pub use self::block_reader::*;
pub use self::section::*;
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use error::*;

pub const BUF_CAPACITY: usize = 10_000_000;

#[derive(Clone, PartialEq, Debug)]
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

#[derive(Clone, PartialEq, Debug)]
pub struct InterfaceId(pub u32);

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
