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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlockType {
    SectionHeader,
    InterfaceDescription,
    ObsoletePacket,
    SimplePacket,
    NameResolution,
    InterfaceStatistics,
    EnhancedPacket,
    IRIGTimestamp,
    Arinc429,
    SystemdJournalExport,
    DecryptionSecrets,
    Custom,
    Hone,
    Sysdig,
    Unknown(u32),
}

impl From<u32> for BlockType {
    fn from(code: u32) -> Self {
        match code {
            0x0A0D_0D0A => BlockType::SectionHeader,
            0x0000_0001 => BlockType::InterfaceDescription,
            0x0000_0002 => BlockType::ObsoletePacket,
            0x0000_0003 => BlockType::SimplePacket,
            0x0000_0004 => BlockType::NameResolution,
            0x0000_0005 => BlockType::InterfaceStatistics,
            0x0000_0006 => BlockType::EnhancedPacket,
            0x0000_0007 => BlockType::IRIGTimestamp,
            0x0000_0008 => BlockType::Arinc429,
            0x0000_0009 => BlockType::SystemdJournalExport,
            0x0000_000A => BlockType::DecryptionSecrets,
            0x0000_0101 | 0x40000102 => BlockType::Hone,
            0x0000_0201..=0x0000_0213 => BlockType::Sysdig,
            0x0000_0BAD | 0x40000BAD => BlockType::Custom,
            n => BlockType::Unknown(n),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Block<'a> {
    SectionHeader(SectionHeader<'a>),
    InterfaceDescription(InterfaceDescription<'a>),
    ObsoletePacket(ObsoletePacket<'a>),
    SimplePacket(SimplePacket),
    NameResolution(NameResolution),
    InterfaceStatistics(InterfaceStatistics<'a>),
    EnhancedPacket(EnhancedPacket<'a>),
    Unparsed(BlockType),
}

impl<'a> Block<'a> {
    pub fn parse<B: ByteOrder + KnownByteOrder>(buf: &[u8]) -> (usize, Result<Block>) {
        if let Err(e) = require_bytes(buf, 8) {
            // Looks like the pcap is truncated.  Let's just skip over the rest.
            return (buf.len(), Err(e));
        }
        let block_type = BlockType::from(B::read_u32(&buf[..4]));
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
            use BlockType as BT;
            let block = match block_type {
                BT::SectionHeader => SectionHeader::parse(block_data, endianness)?.into(),
                BT::InterfaceDescription => InterfaceDescription::parse(block_data, endianness)?.into(),
                BT::ObsoletePacket => ObsoletePacket::parse(block_data, endianness)?.into(),
                BT::SimplePacket => SimplePacket::parse(block_data, endianness)?.into(),
                BT::NameResolution => NameResolution::parse(block_data, endianness)?.into(),
                BT::InterfaceStatistics => InterfaceStatistics::parse(block_data, endianness)?.into(),
                BT::EnhancedPacket => EnhancedPacket::parse(block_data, endianness)?.into(),
                _ => Block::Unparsed(block_type),
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
