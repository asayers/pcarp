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
    /// The isb_starttime option specifies the time the capture started;
    /// time will be stored in two blocks of four octets each. The format of
    /// the timestamp is the same as the one defined in the Enhanced Packet
    /// Block (Section 4.3); the length of a unit of time is specified by
    /// the 'if_tsresol' option (see Figure 10) of the Interface Description
    /// Block referenced by this packet.
    pub isb_starttime: Option<Timestamp>,
    /// The isb_endtime option specifies the time the capture ended; time
    /// will be stored in two blocks of four octets each. The format of the
    /// timestamp is the same as the one defined in the Enhanced Packet Block
    /// (Section 4.3); the length of a unit of time is specified by the
    /// 'if_tsresol' option (see Figure 10) of the Interface Description
    /// Block referenced by this packet.
    pub isb_endtime: Option<Timestamp>,
    /// The isb_ifrecv option specifies the 64-bit unsigned integer number
    /// of packets received from the physical interface starting from the
    /// beginning of the capture.
    pub isb_ifrecv: Option<u64>,
    /// The isb_ifdrop option specifies the 64-bit unsigned integer number
    /// of packets dropped by the interface due to lack of resources starting
    /// from the beginning of the capture.
    pub isb_ifdrop: Option<u64>,
    /// The isb_filteraccept option specifies the 64-bit unsigned integer
    /// number of packets accepted by filter starting from the beginning of
    /// the capture.
    pub isb_filter_accept: Option<u64>,
    /// The isb_osdrop option specifies the 64-bit unsigned integer number of
    /// packets dropped by the operating system starting from the beginning
    /// of the capture.
    pub isb_osdrop: Option<u64>,
    /// The isb_usrdeliv option specifies the 64-bit unsigned integer number
    /// of packets delivered to the user starting from the beginning of the
    /// capture. The value contained in this field can be different from
    /// the value 'isb_filteraccept - isb_osdrop' because some packets could
    /// still be in the OS buffers when the capture ended.
    pub isb_usrdeliv: Option<u64>,
}

impl FromBytes for InterfaceStatistics {
    fn parse<T: Buf>(
        mut buf: T,
        endianness: Endianness,
    ) -> Result<InterfaceStatistics, BlockError> {
        ensure_remaining!(buf, 12);
        let interface_id = read_u32(&mut buf, endianness);
        let timestamp = read_ts(&mut buf, endianness);

        let mut isb_starttime = None;
        let mut isb_endtime = None;
        let mut isb_ifrecv = None;
        let mut isb_ifdrop = None;
        let mut isb_filter_accept = None;
        let mut isb_osdrop = None;
        let mut isb_usrdeliv = None;
        parse_options(buf, endianness, |ty, bytes| {
            match ty {
                2 => isb_starttime = bytes_to_ts(bytes, endianness),
                3 => isb_endtime = bytes_to_ts(bytes, endianness),
                4 => isb_ifrecv = bytes_to_u64(bytes, endianness),
                5 => isb_ifdrop = bytes_to_u64(bytes, endianness),
                6 => isb_filter_accept = bytes_to_u64(bytes, endianness),
                7 => isb_osdrop = bytes_to_u64(bytes, endianness),
                8 => isb_usrdeliv = bytes_to_u64(bytes, endianness),
                _ => (), // Ignore unknown
            }
        });

        Ok(InterfaceStatistics {
            interface_id,
            timestamp,
            isb_starttime,
            isb_endtime,
            isb_ifrecv,
            isb_ifdrop,
            isb_filter_accept,
            isb_osdrop,
            isb_usrdeliv,
        })
    }
}
