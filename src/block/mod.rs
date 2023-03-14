/*! **\[Internal\]** Block definitions.

> Caveat: This is an internal module, and is exposed for the sake of
> interest only.  The API may change in a patch bump.  The user may need to
> enforce invariants.  The documentation may be inaccurate.

That said, if you want to get an idea of how the pcap-ng format works,
take a look at [`Block`](enum.Block.html).

All documentation in this module is taken from [the pcap-ng spec][].  It is
copyright (c) 2018 IETF Trust and the persons identified as the authors of
the linked document. All rights reserved.

[the pcap-ng spec]: https://github.com/pcapng/pcapng
*/

mod epb;
mod idb;
mod isb;
mod nrb;
mod opb;
mod shb;
mod spb;
mod util;

pub use self::epb::*;
pub use self::idb::*;
pub use self::isb::*;
pub use self::nrb::*;
pub use self::opb::*;
pub use self::shb::*;
pub use self::spb::*;
pub use self::util::*;

use crate::{Error, Result};
use byteorder::ByteOrder;
use tracing::*;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Block<'a> {
    SectionHeader(SectionHeader<'a>),               // 0x0A0D0D0A
    InterfaceDescription(InterfaceDescription<'a>), // 0x00000001
    ObsoletePacket(ObsoletePacket<'a>),             // 0x00000002
    SimplePacket(SimplePacket),                     // 0x00000003
    NameResolution(NameResolution),                 // 0x00000004
    InterfaceStatistics(InterfaceStatistics<'a>),   // 0x00000005
    EnhancedPacket(EnhancedPacket<'a>),             // 0x00000006
    IRIGTimestamp,                                  // 0x00000007, ignored
    Arinc429,                                       // 0x00000008, ignored
    Unknown(u32),
}

impl<'a> Block<'a> {
    pub fn parse<B: ByteOrder + KnownByteOrder>(buf: &[u8]) -> (usize, Result<Block>) {
        if let Err(e) = require_bytes(buf, 8) {
            // Looks like the pcap is truncated.  Let's just skip over the rest.
            return (buf.len(), Err(e));
        }
        let block_type = B::read_u32(&buf[..4]);
        let block_length = B::read_u32(&buf[4..8]) as usize;
        let block = || {
            if block_length < 12 {
                return Err(Error::BlockLengthTooShort);
            }
            require_bytes(buf, block_length)?;
            trace!(
                "Got a complete block: type {:x}, len {}",
                block_type,
                block_length
            );
            let body = &buf[8..block_length - 4];
            let block_length_2 = B::read_u32(&buf[block_length - 4..block_length]) as usize;
            if block_length != block_length_2 {
                return Err(Error::BlockLengthMismatch);
            }
            let block = match block_type {
                0x0A0D_0D0A => Block::from(SectionHeader::parse::<B>(body)?),
                0x0000_0001 => Block::from(InterfaceDescription::parse::<B>(body)?),
                0x0000_0002 => Block::from(ObsoletePacket::parse::<B>(body)?),
                0x0000_0003 => Block::from(SimplePacket::parse::<B>(body)?),
                0x0000_0004 => Block::from(NameResolution::parse::<B>(body)?),
                0x0000_0005 => Block::from(InterfaceStatistics::parse::<B>(body)?),
                0x0000_0006 => Block::from(EnhancedPacket::parse::<B>(body)?),
                0x0000_0007 => Block::IRIGTimestamp,
                0x0000_0008 => Block::Arinc429,
                n => Block::Unknown(n),
            };
            Ok(block)
        };
        (block_length, block())
    }
}

impl<'a> From<SectionHeader<'a>> for Block<'a> {
    fn from(x: SectionHeader<'a>) -> Self {
        Block::SectionHeader(x)
    }
}
impl<'a> From<InterfaceDescription<'a>> for Block<'a> {
    fn from(x: InterfaceDescription<'a>) -> Self {
        Block::InterfaceDescription(x)
    }
}
impl<'a> From<ObsoletePacket<'a>> for Block<'a> {
    fn from(x: ObsoletePacket<'a>) -> Self {
        Block::ObsoletePacket(x)
    }
}
impl<'a> From<SimplePacket> for Block<'a> {
    fn from(x: SimplePacket) -> Self {
        Block::SimplePacket(x)
    }
}
impl<'a> From<NameResolution> for Block<'a> {
    fn from(x: NameResolution) -> Self {
        Block::NameResolution(x)
    }
}
impl<'a> From<InterfaceStatistics<'a>> for Block<'a> {
    fn from(x: InterfaceStatistics<'a>) -> Self {
        Block::InterfaceStatistics(x)
    }
}
impl<'a> From<EnhancedPacket<'a>> for Block<'a> {
    fn from(x: EnhancedPacket<'a>) -> Self {
        Block::EnhancedPacket(x)
    }
}
