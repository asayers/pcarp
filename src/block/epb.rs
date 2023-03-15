use crate::block::opts::*;
use crate::block::util::*;
use bytes::{Buf, Bytes};

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
pub struct EnhancedPacket {
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
    pub timestamp: Timestamp,
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
    pub packet_data: Bytes,
    /// The epb_flags option is a 32-bit flags word containing link-layer
    /// information. A complete specification of the allowed flags can be
    /// found in Section 4.3.1.
    pub epb_flags: u32,
    /// The epb_hash option contains a hash of the packet. The first octet
    /// specifies the hashing algorithm, while the following octets contain
    /// the actual hash, whose size depends on the hashing algorithm, and
    /// hence from the value in the first octet. The hashing algorithm can
    /// be: 2s complement (algorithm octet = 0, size = XXX), XOR (algorithm
    /// octet = 1, size=XXX), CRC32 (algorithm octet = 2, size = 4), MD-5
    /// (algorithm octet = 3, size = 16), SHA-1 (algorithm octet = 4, size
    /// = 20), Toeplitz (algorithm octet = 5, size = 4). The hash covers
    /// only the packet, not the header added by the capture driver: this
    /// gives the possibility to calculate it inside the network card. The
    /// hash allows easier comparison/merging of different capture files,
    /// and reliable data transfer between the data acquisition system and
    /// the capture library.
    pub epb_hash: Vec<Bytes>,
    /// The epb_dropcount option is a 64-bit unsigned integer value specifying
    /// the number of packets lost (by the interface and the operating system)
    /// between this packet and the preceding one for the same interface or,
    /// for the first packet for an interface, between this packet and the
    /// start of the capture process.
    pub epb_dropcount: Option<u64>,
    /// The epb_packetid option is a 64-bit unsigned integer that uniquely
    /// identifies the packet. If the same packet is seen by multiple
    /// interfaces and there is a way for the capture application to correlate
    /// them, the same epb_packetid value must be used. An example could
    /// be a router that captures packets on all its interfaces in both
    /// directions. When a packet hits interface A on ingress, an EPB entry
    /// gets created, TTL gets decremented, and right before it egresses on
    /// interface B another EPB entry gets created in the trace file. In this
    /// case, two packets are in the capture file, which are not identical
    /// but the epb_packetid can be used to correlate them.
    pub epb_packetid: Option<u64>,
    /// The epb_queue option is a 32-bit unsigned integer that identifies
    /// on which queue of the interface the specific packet was received.
    pub epb_queue: Option<u32>,
    pub epb_verdict: Vec<Bytes>,
}

impl FromBytes for EnhancedPacket {
    fn parse<T: Buf>(mut buf: T, endianness: Endianness) -> Result<EnhancedPacket, BlockError> {
        ensure_remaining!(buf, 20);
        let interface_id = read_u32(&mut buf, endianness);
        let timestamp = read_ts(&mut buf, endianness);
        let captured_len = read_u32(&mut buf, endianness);
        let packet_len = read_u32(&mut buf, endianness);
        let packet_data = read_bytes(&mut buf, captured_len)?;

        let mut epb_flags = 0;
        let mut epb_hash = vec![];
        let mut epb_dropcount = None;
        let mut epb_packetid = None;
        let mut epb_queue = None;
        let mut epb_verdict = vec![];
        parse_options(buf, endianness, |ty, bytes| {
            match ty {
                2 => {
                    if let Some(x) = bytes_to_u32(bytes, endianness) {
                        epb_flags = x;
                    }
                }
                3 => epb_hash.push(bytes),
                4 => epb_dropcount = bytes_to_u64(bytes, endianness),
                5 => epb_packetid = bytes_to_u64(bytes, endianness),
                6 => epb_queue = bytes_to_u32(bytes, endianness),
                7 => epb_verdict.push(bytes),
                _ => (), // Ignore unknown
            }
        });

        Ok(EnhancedPacket {
            interface_id,
            timestamp,
            captured_len,
            packet_len,
            packet_data,
            epb_flags,
            epb_hash,
            epb_dropcount,
            epb_packetid,
            epb_queue,
            epb_verdict,
        })
    }
}
