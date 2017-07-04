pub const BUF_CAPACITY: usize = 10_000_000;

#[derive(Clone, PartialEq, Debug)]
pub enum Endianness {
    Big,
    Little,
}

pub type Result<T> = ::std::result::Result<T, Error>;

#[derive(Clone, PartialEq, Debug)]
pub enum Error {
    DidntUnderstandMagicNumber([u8;4]),
    UnknownBlockType(u32),
    NotEnoughBytes,
}
