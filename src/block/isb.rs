use crate::block::util::*;
use crate::Result;
use byteorder::ByteOrder;

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
pub struct InterfaceStatistics<'a> {
    /// Specifies the interface these statistics refers to; the correct interface will be the one
    /// whose Interface Description Block (within the current Section of the file) is identified by
    /// same number (see Section 4.2) of this field.
    pub interface_id: u32,
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
            interface_id: B::read_u32(&buf[0..4]),
            timestamp_high: B::read_u32(&buf[4..8]),
            timestamp_low: B::read_u32(&buf[8..12]),
            options: &buf[12..],
        })
    }
}
