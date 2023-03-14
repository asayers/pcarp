use crate::types::*;
use byteorder::ByteOrder;
use std::ops::Range;

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
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EnhancedPacket<'a> {
    /// Specifies the interface this packet comes from; the correct interface will be the one whose
    /// Interface Description Block (within the current Section of the file) is identified by the
    /// same number (see Section 4.2) of this field. The interface ID MUST be valid, which means
    /// that an matching interface description block MUST exist.
    pub interface_id: u32,
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
        require_bytes(buf, 16)?;
        let captured_len = B::read_u32(&buf[12..16]);
        require_bytes(buf, 20 + captured_len as usize)?;
        let timestamp_high = B::read_u32(&buf[4..8]);
        let timestamp_low = B::read_u32(&buf[8..12]);
        Ok(EnhancedPacket {
            interface_id: B::read_u32(&buf[0..4]),
            timestamp: (u64::from(timestamp_high) << 32) + u64::from(timestamp_low),
            captured_len,
            packet_len: B::read_u32(&buf[16..20]),
            packet_data: 20..20 + captured_len as usize,
            options: &buf[20 + captured_len as usize..],
        })
    }
}
