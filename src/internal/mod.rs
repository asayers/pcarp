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
use byteorder::ByteOrder;
use error::*;

pub const BUF_CAPACITY: usize = 10_000_000;

#[derive(Clone, PartialEq, Debug)]
pub enum Endianness {
    Big,
    Little,
}

#[derive(Clone, PartialEq, Debug)]
pub struct InterfaceId(pub u32);

pub trait FromBytes<'a>: Sized {
    fn parse<B: ByteOrder>(buf: &'a [u8]) -> Result<Self>;
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
