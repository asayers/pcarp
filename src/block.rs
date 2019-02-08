/*! Block definitions.  Not meant for consumption.

> **Standard caveat**: Internals are exposed for the sake of interest only.
> The API may change in a patch bump.
> The user may need to enforce invariants.
> The documentation may be inaccurate.

If you want to get an idea of how the pcap-ng format works, take a look at
[`Block`](enum.Block.html).

All documentation in this module is taken from [the pcap-ng spec][].  It is copyright (c) 2018 IETF
Trust and the persons identified as the authors of the linked document. All rights reserved.

[the pcap-ng spec]: https://github.com/pcapng/pcapng
*/

use crate::types::*;
use byteorder::ByteOrder;
use log::*;
use std::ops::Range;

#[derive(Clone, PartialEq, Debug)]
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

/// Defines the most important characteristics of the capture file.
///
/// The Section Header Block (SHB) is mandatory. It identifies the beginning of a section of the
/// capture capture file. The Section Header Block does not contain data but it rather identifies a
/// list of blocks (interfaces, packets) that are logically correlated.
///
/// This documentation is copyright (c) 2018 IETF Trust and the persons identified as the
/// authors of [this document][1]. All rights reserved. Please see the linked document for the full
/// copyright notice.
///
/// [1]: https://github.com/pcapng/pcapng
#[derive(Clone, PartialEq, Debug)]
pub struct SectionHeader<'a> {
    /// Used to distinguish sections that have been saved on little-endian machines from the ones
    /// saved on big-endian machines.
    pub endianness: Endianness,
    /// Number of the current mayor version of the format. Current value is 1. This value should
    /// change if the format changes in such a way that code that reads the new format could not
    /// read the old format (i.e., code to read both formats would have to check the version number
    /// and use different code paths for the two formats) and code that reads the old format could
    /// not read the new format.
    pub major_version: u16,
    /// Number of the current minor version of the format. Current value is 0. This value should
    /// change if the format changes in such a way that code that reads the new format could read
    /// the old format without checking the version number but code that reads the old format could
    /// not read all files in the new format.
    pub minor_version: u16,
    /// A signed 64-bit value specifying the length in octets of the following section, excluding
    /// the Section Header Block itself. This field can be used to skip the section, for faster
    /// navigation inside large files. Section Length equal -1 (0xFFFFFFFFFFFFFFFF) means that the
    /// size of the section is not specified, and the only way to skip the section is to parse the
    /// blocks that it contains. Please note that if this field is valid (i.e. not negative), its
    /// value is always aligned to 32 bits, as all the blocks are aligned to and padded to 32-bit
    /// boundaries. Also, special care should be taken in accessing this field: since the alignment
    /// of all the blocks in the file is 32-bits, this field is not guaranteed to be aligned to a
    /// 64-bit boundary. This could be a problem on 64-bit processors.
    pub section_length: i64,
    /// Optionally, a list of options (formatted according to the rules defined in Section 3.5) can
    /// be present.
    pub options: &'a [u8],
}

impl<'a> FromBytes<'a> for SectionHeader<'a> {
    fn parse<B: ByteOrder + KnownByteOrder>(buf: &'a [u8]) -> Result<SectionHeader<'a>> {
        require_bytes(buf, 16)?;
        Ok(SectionHeader {
            endianness: B::endianness(),
            major_version: B::read_u16(&buf[4..6]),
            minor_version: B::read_u16(&buf[6..8]),
            section_length: B::read_i64(&buf[8..16]),
            options: &buf[16..],
        })
    }
}

/// Defines the most important characteristics of the interface(s) used for capturing traffic. This
/// block is required in certain cases, as described later.
///
/// An Interface Description Block (IDB) is the container for information describing an interface
/// on which packet data is captured.
///
/// Tools that write / read the capture file associate an incrementing 32-bit number (starting from
/// '0') to each Interface Definition Block, called the Interface ID for the interface in question.
/// This number is unique within each Section and identifies the interface to which the IDB refers;
/// it is only unique inside the current section, so, two Sections can have different interfaces
/// identified by the same Interface ID values. This unique identifier is referenced by other
/// blocks, such as Enhanced Packet Blocks and Interface Statistic Blocks, to indicate the
/// interface to which the block refers (such the interface that was used to capture the packet
/// that an Enhanced Packet Block contains or to which the statistics in an Interface Statistic
/// Block refer).
///
/// There must be an Interface Description Block for each interface to which another block refers.
/// Blocks such as an Enhanced Packet Block or an Interface Statistics Block contain an Interface
/// ID value referring to a particular interface, and a Simple Packet Block implicitly refers to an
/// interface with an Interface ID of 0. If the file does not contain any blocks that use an
/// Interface ID, then the file does not need to have any IDBs.
///
/// An Interface Description Block is valid only inside the section to which it belongs.
///
/// This documentation is copyright (c) 2018 IETF Trust and the persons identified as the
/// authors of [this document][1]. All rights reserved. Please see the linked document for the full
/// copyright notice.
///
/// [1]: https://github.com/pcapng/pcapng
#[derive(Clone, PartialEq, Debug)]
pub struct InterfaceDescription<'a> {
    /// A value that defines the link layer type of this interface. The list of Standardized Link
    /// Layer Type codes is available in the tcpdump.org link-layer header types registry.
    pub link_type: LinkType,
    /// Maximum number of octets captured from each packet. The portion of each packet that exceeds
    /// this value will not be stored in the file. A value of zero indicates no limit.
    pub snap_len: u32,
    /// Optionally, a list of options (formatted according to the rules defined in Section 3.5) can
    /// be present.
    pub options: &'a [u8],
}

impl<'a> FromBytes<'a> for InterfaceDescription<'a> {
    fn parse<B: ByteOrder>(buf: &'a [u8]) -> Result<InterfaceDescription<'a>> {
        require_bytes(buf, 8)?;
        let lt = B::read_u16(&buf[0..2]);
        Ok(InterfaceDescription {
            link_type: LinkType::from_u16(lt),
            snap_len: B::read_u32(&buf[4..8]),
            options: &buf[8..],
        })
    }
}

/// Contains a single captured packet, or a portion of it. It represents an evolution of the
/// original, now obsolete, Packet Block. If this appears in a file, an Interface Description Block
/// is also required, before this block.
///
/// An Enhanced Packet Block (EPB) is the standard container for storing the packets coming from
/// the network. The Enhanced Packet Block is optional because packets can be stored either by
/// means of this block or the Simple Packet Block, which can be used to speed up capture file
/// generation; or a file may have no packets in it.
///
/// The Enhanced Packet Block is an improvement over the original, now obsolete, Packet Block:
///
/// * it stores the Interface Identifier as a 32-bit integer value. This is a requirement when a
///   capture stores packets coming from a large number of interfaces
/// * unlike the Packet Block, the number of packets dropped by the capture system between this
///   packet and the previous one is not stored in the header, but rather in an option of the block
///   itself.
///
/// This documentation is copyright (c) 2018 IETF Trust and the persons identified as the
/// authors of [this document][1]. All rights reserved. Please see the linked document for the full
/// copyright notice.
///
/// [1]: https://github.com/pcapng/pcapng
#[derive(Clone, PartialEq, Debug)]
pub struct EnhancedPacket<'a> {
    /// Specifies the interface this packet comes from; the correct interface will be the one whose
    /// Interface Description Block (within the current Section of the file) is identified by the
    /// same number (see Section 4.2) of this field. The interface ID MUST be valid, which means
    /// that an matching interface description block MUST exist.
    pub interface_id: InterfaceId,
    /// Upper 32 bits and lower 32 bits of a 64-bit timestamp. The timestamp is a single 64-bit
    /// unsigned integer that represents the number of units of time that have elapsed since
    /// 1970-01-01 00:00:00 UTC. The length of a unit of time is specified by the 'if_tsresol'
    /// option (see Figure 10) of the Interface Description block referenced by this packet. Note
    /// that, unlike timestamps in the libpcap file format, timestamps in Enhanced Packet Blocks
    /// are not saved as two 32-bit values that represent the seconds and microseconds that have
    /// elapsed since 1970-01-01 00:00:00 UTC. Timestamps in Enhanced Packet Blocks are saved as
    /// two 32-bit words that represent the upper and lower 32 bits of a single 64-bit quantity.
    pub timestamp: u64,
    /// Number of octets captured from the packet (i.e. the length of the Packet Data field). It
    /// will be the minimum value among the Original Packet Length and the snapshot length for the
    /// interface (SnapLen, defined in Figure 10). The value of this field does not include the
    /// padding octets added at the end of the Packet Data field to align the Packet Data field to
    /// a 32-bit boundary.
    pub captured_len: u32,
    /// Actual length of the packet when it was transmitted on the network. It can be different
    /// from Captured Packet Length if the packet has been truncated by the capture process.
    pub packet_len: u32,
    /// The data coming from the network, including link-layer headers. The actual length of this
    /// field is Captured Packet Length plus the padding to a 32-bit boundary. The format of the
    /// link-layer headers depends on the LinkType field specified in the Interface Description
    /// Block (see Section 4.2) and it is specified in the entry for that format in the the
    /// tcpdump.org link-layer header types registry.
    pub packet_data: Range<usize>,
    /// Optionally, a list of options (formatted according to the rules defined in Section 3.5) can
    /// be present.
    pub options: &'a [u8],
}

impl<'a> FromBytes<'a> for EnhancedPacket<'a> {
    fn parse<B: ByteOrder>(buf: &'a [u8]) -> Result<EnhancedPacket<'a>> {
        let captured_len = B::read_u32(&buf[12..16]);
        require_bytes(buf, 20 + captured_len as usize)?;
        let timestamp_high = B::read_u32(&buf[4..8]);
        let timestamp_low = B::read_u32(&buf[8..12]);
        Ok(EnhancedPacket {
            interface_id: InterfaceId(B::read_u32(&buf[0..4])),
            timestamp: (u64::from(timestamp_high) << 32) + u64::from(timestamp_low),
            captured_len,
            packet_len: B::read_u32(&buf[16..20]),
            packet_data: 20..20 + captured_len as usize,
            options: &buf[20 + captured_len as usize..],
        })
    }
}

/// Contains a single captured packet, or a portion of it, with only a minimal set of information
/// about it. If this appears in a file, an Interface Description Block is also required, before
/// this block.
///
/// The Simple Packet Block (SPB) is a lightweight container for storing the packets coming from
/// the network. Its presence is optional.
///
/// A Simple Packet Block is similar to an Enhanced Packet Block (see Section 4.3), but it is
/// smaller, simpler to process and contains only a minimal set of information. This block is
/// preferred to the standard Enhanced Packet Block when performance or space occupation are
/// critical factors, such as in sustained traffic capture applications. A capture file can contain
/// both Enhanced Packet Blocks and Simple Packet Blocks: for example, a capture tool could switch
/// from Enhanced Packet Blocks to Simple Packet Blocks when the hardware resources become
/// critical.
///
/// The Simple Packet Block does not contain the Interface ID field. Therefore, it MUST be assumed
/// that all the Simple Packet Blocks have been captured on the interface previously specified in
/// the first Interface Description Block.
///
/// This documentation is copyright (c) 2018 IETF Trust and the persons identified as the
/// authors of [this document][1]. All rights reserved. Please see the linked document for the full
/// copyright notice.
///
/// [1]: https://github.com/pcapng/pcapng
#[derive(Clone, PartialEq, Debug)]
pub struct SimplePacket {
    /// Actual length of the packet when it was transmitted on the network. It can be different
    /// from length of the Packet Data field's length if the packet has been truncated by the
    /// capture process, in which case the SnapLen value in Section 4.2 will be less than this
    /// Original Packet Length value, and the SnapLen value MUST be used to determine the size of
    /// the Packet Data field length.
    pub packet_len: u32,
    /// The data coming from the network, including link-layer headers. The length of this field
    /// can be derived from the field Block Total Length, present in the Block Header, and it is
    /// the minimum value among the SnapLen (present in the Interface Description Block) and the
    /// Original Packet Length (present in this header). The format of the data within this Packet
    /// Data field depends on the LinkType field specified in the Interface Description Block (see
    /// Section 4.2) and it is specified in the entry for that format in the tcpdump.org link-layer
    /// header types registry.
    pub packet_data: Range<usize>,
}

impl<'a> FromBytes<'a> for SimplePacket {
    fn parse<B: ByteOrder>(buf: &[u8]) -> Result<SimplePacket> {
        let packet_len = B::read_u32(&buf[0..4]);
        require_bytes(buf, 4 + packet_len as usize)?;
        Ok(SimplePacket {
            packet_len,
            packet_data: 4..4 + packet_len as usize,
        })
    }
}

/// Defines the mapping from numeric addresses present in the packet capture and the canonical name
/// counterpart.
///
/// The Name Resolution Block (NRB) is used to support the correlation of numeric addresses
/// (present in the captured packets) and their corresponding canonical names and it is optional.
/// Having the literal names saved in the file prevents the need for performing name resolution at
/// a later time, when the association between names and addresses may be different from the one in
/// use at capture time. Moreover, the NRB avoids the need for issuing a lot of DNS requests every
/// time the trace capture is opened, and also provides name resolution when reading the capture
/// with a machine not connected to the network.
///
/// A Name Resolution Block is often placed at the beginning of the file, but no assumptions can be
/// taken about its position. Multiple NRBs can exist in a pcapng file, either due to memory
/// constraints or because additional name resolutions were performed by file processing tools,
/// like network analyzers.
///
/// A Name Resolution Block need not contain any Records, except the nrb_record_end Record which
/// MUST be the last Record. The addresses and names in NRB Records MAY be repeated multiple times;
/// i.e., the same IP address may resolve to multiple names, the same name may resolve to the
/// multiple IP addresses, and even the same address-to-name pair may appear multiple times, in the
/// same NRB or across NRBs.
///
/// This documentation is copyright (c) 2018 IETF Trust and the persons identified as the
/// authors of [this document][1]. All rights reserved. Please see the linked document for the full
/// copyright notice.
///
/// [1]: https://github.com/pcapng/pcapng
#[derive(Clone, PartialEq, Debug)]
pub struct NameResolution {
    /// Zero or more Name Resolution Records (in the TLV format), each of which contains an
    /// association between a network address and a name. An nrb_record_end MUST be added after the
    /// last Record, and MUST exist even if there are no other Records in the NRB.
    pub record_values: Vec<u8>, // TODO
}

impl<'a> FromBytes<'a> for NameResolution {
    fn parse<B: ByteOrder>(buf: &[u8]) -> Result<NameResolution> {
        Ok(NameResolution {
            record_values: Vec::from(buf),
        })
    }
}

/// Defines how to store some statistical data (e.g. packet dropped, etc) which can be useful to
/// understand the conditions in which the capture has been made. If this appears in a file, an
/// Interface Description Block is also required, before this block.
///
/// The Interface Statistics Block (ISB) contains the capture statistics for a given interface and
/// it is optional. The statistics are referred to the interface defined in the current Section
/// identified by the Interface ID field. An Interface Statistics Block is normally placed at the
/// end of the file, but no assumptions can be taken about its position - it can even appear
/// multiple times for the same interface.
///
/// This documentation is copyright (c) 2018 IETF Trust and the persons identified as the
/// authors of [this document][1]. All rights reserved. Please see the linked document for the full
/// copyright notice.
///
/// [1]: https://github.com/pcapng/pcapng
#[derive(Clone, PartialEq, Debug)]
pub struct InterfaceStatistics<'a> {
    /// Specifies the interface these statistics refers to; the correct interface will be the one
    /// whose Interface Description Block (within the current Section of the file) is identified by
    /// same number (see Section 4.2) of this field.
    pub interface_id: InterfaceId,
    /// Time this statistics refers to. The format of the timestamp is the same already defined in
    /// the Enhanced Packet Block (Section 4.3).
    pub timestamp_high: u32,
    pub timestamp_low: u32,
    /// Optionally, a list of options (formatted according to the rules defined in Section 3.5) can
    /// be present.
    pub options: &'a [u8],
}

impl<'a> FromBytes<'a> for InterfaceStatistics<'a> {
    fn parse<B: ByteOrder>(buf: &'a [u8]) -> Result<InterfaceStatistics<'a>> {
        require_bytes(buf, 12)?;
        Ok(InterfaceStatistics {
            interface_id: InterfaceId(B::read_u32(&buf[0..4])),
            timestamp_high: B::read_u32(&buf[4..8]),
            timestamp_low: B::read_u32(&buf[8..12]),
            options: &buf[12..],
        })
    }
}

/// Contains a single captured packet, or a portion of it. It is OBSOLETE, and superseded by the
/// Enhanced Packet Block.
///
/// The Packet Block is obsolete, and MUST NOT be used in new files. Use the Enhanced Packet Block
/// or Simple Packet Block instead. This section is for historical reference only.
///
/// A Packet Block was a container for storing packets coming from the network.
///
/// This documentation is copyright (c) 2018 IETF Trust and the persons identified as the
/// authors of [this document][1]. All rights reserved. Please see the linked document for the full
/// copyright notice.
///
/// [1]: https://github.com/pcapng/pcapng
#[derive(Clone, PartialEq, Debug)]
pub struct ObsoletePacket<'a> {
    /// Specifies the interface this packet comes from; the correct interface will be the one whose
    /// Interface Description Block (within the current Section of the file) is identified by the
    /// same number (see Section 4.2) of this field. The interface ID MUST be valid, which means
    /// that an matching interface description block MUST exist.
    pub interface_id: InterfaceId,
    /// A local drop counter. It specifies the number of packets lost (by the interface and the
    /// operating system) between this packet and the preceding one. The value xFFFF (in
    /// hexadecimal) is reserved for those systems in which this information is not available.
    pub drops_count: u16,
    /// Timestamp of the packet. The format of the timestamp is the same as was already defined for
    /// the Enhanced Packet Block (Section 4.3).
    pub timestamp: u64, // FIXME
    /// Number of octets captured from the packet (i.e. the length of the Packet Data field). It
    /// will be the minimum value among the Original Packet Length and the snapshot length for the
    /// interface (SnapLen, defined in Figure 10). The value of this field does not include the
    /// padding octets added at the end of the Packet Data field to align the Packet Data field to
    /// a 32-bit boundary.
    pub captured_len: u32,
    /// Actual length of the packet when it was transmitted on the network. It can be different
    /// from Captured Packet Length if the packet has been truncated by the capture process.
    pub packet_len: u32,
    /// The data coming from the network, including link-layer headers. The actual length of this
    /// field is Captured Packet Length plus the padding to a 32-bit boundary. The format of the
    /// link-layer headers depends on the LinkType field specified in the Interface Description
    /// Block (see Section 4.2) and it is specified in the entry for that format in the the
    /// tcpdump.org link-layer header types registry.
    pub packet_data: Range<usize>,
    /// Optionally, a list of options (formatted according to the rules defined in Section 3.5) can
    /// be present.
    pub options: &'a [u8],
}

impl<'a> FromBytes<'a> for ObsoletePacket<'a> {
    fn parse<B: ByteOrder>(buf: &'a [u8]) -> Result<ObsoletePacket<'a>> {
        let captured_len = B::read_u32(&buf[12..16]);
        require_bytes(buf, 20 + captured_len as usize)?;
        let timestamp_high = B::read_u32(&buf[4..8]);
        let timestamp_low = B::read_u32(&buf[8..12]);
        Ok(ObsoletePacket {
            interface_id: InterfaceId(u32::from(B::read_u16(&buf[0..2]))),
            drops_count: B::read_u16(&buf[2..4]),
            timestamp: (u64::from(timestamp_high) << 4) + u64::from(timestamp_low),
            captured_len,
            packet_len: B::read_u32(&buf[16..20]),
            packet_data: 20..20 + captured_len as usize,
            options: &buf[20 + captured_len as usize..],
        })
    }
}
