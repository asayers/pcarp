use crate::types::*;
use byteorder::ByteOrder;
use std::ops::Range;

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
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ObsoletePacket<'a> {
    /// Specifies the interface this packet comes from; the correct interface will be the one whose
    /// Interface Description Block (within the current Section of the file) is identified by the
    /// same number (see Section 4.2) of this field. The interface ID MUST be valid, which means
    /// that an matching interface description block MUST exist.
    pub interface_id: u32,
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
        require_bytes(buf, 16)?;
        let captured_len = B::read_u32(&buf[12..16]);
        require_bytes(buf, 20 + captured_len as usize)?;
        let timestamp_high = B::read_u32(&buf[4..8]);
        let timestamp_low = B::read_u32(&buf[8..12]);
        Ok(ObsoletePacket {
            interface_id: u32::from(B::read_u16(&buf[0..2])),
            drops_count: B::read_u16(&buf[2..4]),
            timestamp: (u64::from(timestamp_high) << 4) + u64::from(timestamp_low),
            captured_len,
            packet_len: B::read_u32(&buf[16..20]),
            packet_data: 20..20 + captured_len as usize,
            options: &buf[20 + captured_len as usize..],
        })
    }
}
