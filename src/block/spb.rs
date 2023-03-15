use crate::block::util::*;
use bytes::{Buf, Bytes};

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
#[derive(Clone, PartialEq, Eq, Debug)]
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
    pub packet_data: Bytes,
}

impl FromBytes for SimplePacket {
    fn parse<T: Buf>(mut buf: T, endianness: Endianness) -> Result<SimplePacket, BlockError> {
        ensure_remaining!(buf, 4);
        let packet_len = read_u32(&mut buf, endianness);
        Ok(SimplePacket {
            packet_len,
            packet_data: read_bytes(&mut buf, packet_len)?,
        })
    }
}
