mod block;
mod block_reader;
mod section;

pub use self::block::*;
pub use self::block_reader::*;
pub use self::section::*;
use types::*;

pub const BUF_CAPACITY: usize = 10_000_000;

#[derive(Clone, PartialEq, Debug)]
pub enum Endianness {
    Big,
    Little,
}

#[derive(Clone, PartialEq, Debug)]
pub struct InterfaceId(pub u32);

pub fn require_bytes(buf: &[u8], len: usize) -> Result<()> {
    if buf.len() < len {
        Err(Error::NotEnoughBytes(len, buf.len()))
    } else {
        Ok(())
    }
}
