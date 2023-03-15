use crate::iface::LinkType;
use bytes::Buf;
use tracing::*;

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
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InterfaceDescription {
    /// A value that defines the link layer type of this interface. The list of Standardized Link
    /// Layer Type codes is available in the tcpdump.org link-layer header types registry.
    pub link_type: LinkType,
    /// Maximum number of octets captured from each packet. The portion of each packet that exceeds
    /// this value will not be stored in the file. A value of zero indicates no limit.
    pub snap_len: u32,
    /// Optionally, a list of options (formatted according to the rules defined in Section 3.5) can
    /// be present.
    pub options: Bytes,
}

impl FromBytes for InterfaceDescription {
    fn parse<T: Buf>(
        mut buf: T,
        endianness: Endianness,
    ) -> Result<InterfaceDescription, BlockError> {
        ensure_remaining!(buf, 8);
        let link_type = {
            let code = read_u16(&mut buf, endianness);
            buf.advance(2); // 16 bits of padding
            LinkType::from_u16(code)
        };
        let snap_len = read_u32(&mut buf, endianness);
        let options = buf.copy_to_bytes(buf.remaining());
        Ok(InterfaceDescription {
            link_type,
            snap_len,
            options,
        })
    }
}
