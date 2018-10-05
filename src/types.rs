use std::io;
use std::result;

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "Didn't understand magic number {:?}", _0)]
    DidntUnderstandMagicNumber([u8; 4]),
    #[fail(display = "Unknown block type {}", _0)]
    UnknownBlockType(u32),
    #[fail(display = "Unknown link type {}", _0)]
    UnknownLinkType(u16),
    #[fail(display = "Not enough bytes (expected {}, saw {})", _0, _1)]
    NotEnoughBytes(/* expected */ usize, /* actual */ usize),
    #[fail(display = "Zero bytes")]
    ZeroBytes,
    #[fail(display = "Section didn't start with an SHB")]
    DidntStartWithSHB,
    #[fail(display = "IO error: {}", _0)]
    IO(#[cause] io::Error),
}

impl From<io::Error> for Error {
    fn from(x: io::Error) -> Error {
        Error::IO(x)
    }
}
