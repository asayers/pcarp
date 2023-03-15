use crate::block::opts::*;
use crate::block::util::*;
use bytes::Buf;

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
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InterfaceStatistics {
    /// Specifies the interface these statistics refers to; the correct interface will be the one
    /// whose Interface Description Block (within the current Section of the file) is identified by
    /// same number (see Section 4.2) of this field.
    pub interface_id: u32,
    /// Time this statistics refers to. The format of the timestamp is the same already defined in
    /// the Enhanced Packet Block (Section 4.3).
    pub timestamp: Timestamp,
    /// Optionally, a list of options (formatted according to the rules defined in Section 3.5) can
    /// be present.
    pub options: Bytes,
}

impl FromBytes for InterfaceStatistics {
    fn parse<T: Buf>(
        mut buf: T,
        endianness: Endianness,
    ) -> Result<InterfaceStatistics, BlockError> {
        ensure_remaining!(buf, 12);
        let interface_id = read_u32(&mut buf, endianness);
        let timestamp = read_ts(&mut buf, endianness);
        let options = buf.copy_to_bytes(buf.remaining());
        Ok(InterfaceStatistics {
            interface_id,
            timestamp,
            options,
        })
    }
}
