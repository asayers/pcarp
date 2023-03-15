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
mod frame;
mod idb;
mod isb;
mod nrb;
mod opb;
mod rdr;
mod shb;
mod spb;
mod util;

pub use self::epb::*;
pub use self::frame::*;
pub use self::idb::*;
pub use self::isb::*;
pub use self::nrb::*;
pub use self::opb::*;
pub use self::rdr::*;
pub use self::shb::*;
pub use self::spb::*;
pub use self::util::*;

use bytes::{Buf, Bytes};
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
pub enum Block {
    SectionHeader(SectionHeader),
    InterfaceDescription(InterfaceDescription),
    ObsoletePacket(ObsoletePacket),
    SimplePacket(SimplePacket),
    NameResolution(NameResolution),
    InterfaceStatistics(InterfaceStatistics),
    EnhancedPacket(EnhancedPacket),
    Unparsed(BlockType),
}

impl Block {
    pub(crate) fn parse(
        block_type: BlockType,
        block_data: impl Buf,
        endianness: Endianness,
    ) -> Result<Block, BlockError> {
        use BlockType as BT;
        Ok(match block_type {
            BT::SectionHeader => SectionHeader::parse(block_data, endianness)?.into(),
            BT::InterfaceDescription => InterfaceDescription::parse(block_data, endianness)?.into(),
            BT::ObsoletePacket => ObsoletePacket::parse(block_data, endianness)?.into(),
            BT::SimplePacket => SimplePacket::parse(block_data, endianness)?.into(),
            BT::NameResolution => NameResolution::parse(block_data, endianness)?.into(),
            BT::InterfaceStatistics => InterfaceStatistics::parse(block_data, endianness)?.into(),
            BT::EnhancedPacket => EnhancedPacket::parse(block_data, endianness)?.into(),
            _ => Block::Unparsed(block_type),
        })
    }

    pub(crate) fn into_pkt(self) -> Option<(Option<(Timestamp, u32)>, Bytes)> {
        match self {
            Block::EnhancedPacket(pkt) => {
                Some((Some((pkt.timestamp, pkt.interface_id)), pkt.packet_data))
            }
            Block::SimplePacket(pkt) => Some((None, pkt.packet_data)),
            Block::ObsoletePacket(pkt) => Some((
                Some((pkt.timestamp, u32::from(pkt.interface_id))),
                pkt.packet_data,
            )),
            _ => None,
        }
    }
}

impl From<SectionHeader> for Block {
    fn from(x: SectionHeader) -> Self {
        Block::SectionHeader(x)
    }
}
impl From<InterfaceDescription> for Block {
    fn from(x: InterfaceDescription) -> Self {
        Block::InterfaceDescription(x)
    }
}
impl From<ObsoletePacket> for Block {
    fn from(x: ObsoletePacket) -> Self {
        Block::ObsoletePacket(x)
    }
}
impl From<SimplePacket> for Block {
    fn from(x: SimplePacket) -> Self {
        Block::SimplePacket(x)
    }
}
impl From<NameResolution> for Block {
    fn from(x: NameResolution) -> Self {
        Block::NameResolution(x)
    }
}
impl From<InterfaceStatistics> for Block {
    fn from(x: InterfaceStatistics) -> Self {
        Block::InterfaceStatistics(x)
    }
}
impl From<EnhancedPacket> for Block {
    fn from(x: EnhancedPacket) -> Self {
        Block::EnhancedPacket(x)
    }
}
