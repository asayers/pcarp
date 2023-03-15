use crate::block::opts::*;
use crate::block::util::*;
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
    pub snap_len: Option<u32>,
    /// The if_name option is a UTF-8 string containing the name of the
    /// device used to capture data. The string is not zero-terminated.
    pub if_name: String,
    /// The if_description option is a UTF-8 string containing the description
    /// of the device used to capture data. The string is not zero-terminated.
    pub if_description: String,
    /// The if_IPv4addr option is an IPv4 network address and corresponding
    /// netmask for the interface. The first four octets are the IP address,
    /// and the next four octets are the netmask. This option can be repeated
    /// multiple times within the same Interface Description Block when
    /// multiple IPv4 addresses are assigned to the interface. Note that
    /// the IP address and netmask are both treated as four octets, one
    /// for each octet of the address or mask; they are not 32-bit numbers,
    /// and thus the endianness of the SHB does not affect this field's value.
    pub if_ipv4_addr: Vec<[u8; 8]>,
    /// The if_IPv6addr option is an IPv6 network address and corresponding
    /// prefix length for the interface. The first 16 octets are the IP
    /// address and the next octet is the prefix length. This option can be
    /// repeated multiple times within the same Interface Description Block
    /// when multiple IPv6 addresses are assigned to the interface.
    pub if_ipv6_addr: Vec<[u8; 17]>,
    /// The if_MACaddr option is the Interface Hardware MAC address (48 bits),
    /// if available.
    pub if_mac_addr: Option<[u8; 6]>,
    /// The if_EUIaddr option is the Interface Hardware EUI address (64 bits),
    /// if available.
    pub if_eui_addr: Option<[u8; 8]>,
    /// The if_speed option is a 64-bit unsigned value indicating the
    /// interface speed, in bits per second.
    pub if_speed: Option<u64>,
    /// The if_tsresol option identifies the resolution of timestamps. If
    /// the Most Significant Bit is equal to zero, the remaining bits
    /// indicates the resolution of the timestamp as a negative power of 10
    /// (e.g. 6 means microsecond resolution, timestamps are the number of
    /// microseconds since 1970-01-01 00:00:00 UTC). If the Most Significant
    /// Bit is equal to one, the remaining bits indicates the resolution as
    /// negative power of 2 (e.g. 10 means 1/1024 of second). If this option
    /// is not present, a resolution of 10^-6 is assumed (i.e. timestamps
    /// have the same resolution of the standard 'libpcap' timestamps).
    pub if_tsresol: u32,
    /// The if_tzone option identifies the time zone for GMT support.
    pub if_tzone: Option<[u8; 4]>,
    /// The if_filter option identifies the filter (e.g. "capture only TCP
    /// traffic") used to capture traffic. The first octet of the Option Data
    /// keeps a code of the filter used (e.g. if this is a libpcap string,
    /// or BPF bytecode, and more).
    pub if_filter: String,
    /// The if_os option is a UTF-8 string containing the name of the operating
    /// system of the machine in which this interface is installed. This can
    /// be different from the same information that can be contained by the
    /// Section Header Block (Section 4.1) because the capture can have been
    /// done on a remote machine. The string is not zero-terminated.
    pub if_os: String,
    /// The if_fcslen option is an 8-bit unsigned integer value that
    /// specifies the length of the Frame Check Sequence (in bits) for this
    /// interface. For link layers whose FCS length can change during time,
    /// the Enhanced Packet Block epb_flags Option can be used in each
    /// Enhanced Packet Block (see Section 4.3.1).
    pub if_fcslen: Option<[u8; 1]>,
    /// The if_tsoffset option is a 64-bit signed integer value that specifies
    /// an offset (in seconds) that must be added to the timestamp of each
    /// packet to obtain the absolute timestamp of a packet. If the option
    /// is missing, the timestamps stored in the packet MUST be considered
    /// absolute timestamps. The time zone of the offset can be specified
    /// with the option if_tzone.
    pub if_tsoffset: Option<[u8; 8]>,
    /// The if_hardware option is a UTF-8 string containing the description
    /// of the interface hardware. The string is not zero-terminated.
    pub if_hardware: String,
    /// The if_txrxspeeds option is a 64-bit unsigned value indicating the
    /// interface transmit speed in bits per second.
    pub if_txspeed: Option<[u8; 8]>,
    /// The if_rxspeed option is a 64-bit unsigned value indicating the
    /// interface receive speed, in bits per second.
    pub if_rxspeed: Option<[u8; 8]>,
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
        let snap_len = match read_u32(&mut buf, endianness) {
            0 => None,
            x => Some(x),
        };

        let mut if_name = String::new();
        let mut if_description = String::new();
        let mut if_ipv4_addr = vec![];
        let mut if_ipv6_addr = vec![];
        let mut if_mac_addr = None;
        let mut if_eui_addr = None;
        let mut if_speed = None;
        let mut if_tsresol = 1_000_000;
        let mut if_tzone = None;
        let mut if_filter = String::new();
        let mut if_os = String::new();
        let mut if_fcslen = None;
        let mut if_tsoffset = None;
        let mut if_hardware = String::new();
        let mut if_txspeed = None;
        let mut if_rxspeed = None;
        parse_options(buf, endianness, |ty, bytes| {
            match ty {
                2 => if_name = bytes_to_string(bytes),
                3 => if_description = bytes_to_string(bytes),
                4 => {
                    if let Some(x) = bytes_to_array(bytes) {
                        if_ipv4_addr.push(x)
                    }
                }
                5 => {
                    if let Some(x) = bytes_to_array(bytes) {
                        if_ipv6_addr.push(x)
                    }
                }
                6 => if_mac_addr = bytes_to_array(bytes),
                7 => if_eui_addr = bytes_to_array(bytes),
                8 => if_speed = bytes_to_u64(bytes, endianness),
                9 => {
                    if let Some([v]) = bytes_to_array(bytes) {
                        let exp = u32::from(v & 0b0111_1111);
                        let base = match v >> 7 {
                            0 => 10_u32,
                            1 => 2_u32,
                            _ => unreachable!(),
                        };
                        if let Some(x) = base.checked_pow(exp) {
                            if_tsresol = x;
                        } else {
                            warn!(
                                "Saw an interface with a timestamp resolution \
                                of {base}^{exp}.  The timestamps of packets \
                                captured from this interface won't fit into  \
                                a u32."
                            )
                        }
                    }
                }
                10 => if_tzone = bytes_to_array(bytes),
                11 => if_filter = bytes_to_string(bytes),
                12 => if_os = bytes_to_string(bytes),
                13 => if_fcslen = bytes_to_array(bytes),
                14 => if_tsoffset = bytes_to_array(bytes),
                15 => if_hardware = bytes_to_string(bytes),
                16 => if_txspeed = bytes_to_array(bytes),
                17 => if_rxspeed = bytes_to_array(bytes),
                _ => (), // Ignore unknown
            }
        });

        Ok(InterfaceDescription {
            link_type,
            snap_len,
            if_name,
            if_description,
            if_ipv4_addr,
            if_ipv6_addr,
            if_mac_addr,
            if_eui_addr,
            if_speed,
            if_tsresol,
            if_tzone,
            if_filter,
            if_os,
            if_fcslen,
            if_tsoffset,
            if_hardware,
            if_txspeed,
            if_rxspeed,
        })
    }
}
