use crate::block::*;
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use std::ops::Range;
use std::result;
use std::time::SystemTime;
use thiserror::Error;

pub type Result<T, E = Error> = result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Didn't understand magic number {0:?}")]
    DidntUnderstandMagicNumber([u8; 4]),
    #[error("Not enough bytes (expected {expected}, saw {actual})")]
    NotEnoughBytes { expected: usize, actual: usize },
    #[error("Section didn't start with an SHB")]
    DidntStartWithSHB,
    #[error("Block's start and end lengths don't match")]
    BlockLengthMismatch,
    #[error("Block length must be at least 12 bytes")]
    BlockLengthTooShort,
    #[error("option_len for if_tsresol should be 1 but got {0}")]
    WrongOptionLen(usize),
    #[error("There were more options after an option with type 0")]
    OptionsAfterEnd,
    #[error("This timestamp resolution won't fit into a u32")]
    ResolutionTooHigh,
    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),
}

/// A single captured packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet<'a> {
    /// The time at which the packet was captured.  The resolution depends on the interface.
    pub timestamp: Option<SystemTime>,
    /// The interface used to capture this packet.
    pub interface: Option<&'a Interface>,
    /// The raw packet data.
    pub data: &'a [u8],
    /// The location of the data in the underlying reader.
    pub data_offset: Range<usize>,
}

/// The type of physical link backing a network interface.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum LinkType {
    /// No link layer information. A packet saved with this link layer contains a raw L3 packet
    /// preceded by a 32-bit host-byte-order AF_ value indicating the specific L3 type.
    NULL,
    /// D/I/X and 802.3 Ethernet
    ETHERNET,
    /// Experimental Ethernet (3Mb)
    EXP_ETHERNET,
    /// Amateur Radio AX.25
    AX24,
    /// Proteon ProNET Token Ring
    PRONET,
    /// Chaos
    CHAOS,
    /// IEEE 802 Networks
    TOKEN_RING,
    /// ARCNET, with BSD-style header
    ARCNET,
    /// Serial Line IP
    SLIP,
    /// Point-to-point Protocol
    PPP,
    /// FDDI
    FDDI,
    /// PPP in HDLC-like framing
    PPP_HDLC,
    /// NetBSD PPP-over-Ethernet
    PPP_ETHER,
    /// Symantec Enterprise Firewall
    SYMANTEC_FIREWALL,
    /// LLC/SNAP-encapsulated ATM
    ATM_RFC1483,
    /// Raw IP
    RAW,
    /// BSD/OS SLIP BPF header
    SLIP_BSDOS,
    /// BSD/OS PPP BPF header
    PPP_BSDOS,
    /// Cisco HDLC
    C_HDLC,
    /// IEEE 802.11 (wireless)
    IEEE802_11,
    /// Linux Classical IP over ATM
    ATM_CLIP,
    /// Frame Relay
    FRELAY,
    /// OpenBSD loopback
    LOOP,
    /// OpenBSD IPSEC enc
    ENC,
    /// ATM LANE + 802.3 (Reserved for future use)
    LANE8023,
    /// NetBSD HIPPI (Reserved for future use)
    HIPPI,
    /// NetBSD HDLC framing (Reserved for future use)
    HDLC,
    /// Linux cooked socket capture
    LINUX_SLL,
    /// Apple LocalTalk hardware
    LTALK,
    /// Acorn Econet
    ECONET,
    /// Reserved for use with OpenBSD ipfilter
    IPFILTER,
    /// OpenBSD DLT_PFLOG
    PFLOG,
    /// For Cisco-internal use
    CISCO_IOS,
    /// 802.11+Prism II monitor mode
    PRISM_HEADER,
    /// FreeBSD Aironet driver stuff
    AIRONET_HEADER,
    /// Reserved for Siemens HiPath HDLC
    HHDLC,
    /// RFC 2625 IP-over-Fibre Channel
    IP_OVER_FC,
    /// Solaris+SunATM
    SUNATM,
    /// RapidIO - Reserved as per request from Kent Dahlgren <kent@praesum.com> for private use.
    RIO,
    /// PCI Express - Reserved as per request from Kent Dahlgren <kent@praesum.com> for private
    /// use.
    PCI_EXP,
    /// Xilinx Aurora link layer - Reserved as per request from Kent Dahlgren <kent@praesum.com>
    /// for private use.
    AURORA,
    /// 802.11 plus BSD radio header
    IEEE802_11_RADIO,
    /// Tazmen Sniffer Protocol - Reserved for the TZSP encapsulation, as per request from Chris
    /// Waters <chris.waters@networkchemistry.com> TZSP is a generic encapsulation for any other
    /// link type, which includes a means to include meta-information with the packet, e.g. signal
    /// strength and channel for 802.11 packets.
    TZSP,
    /// Linux-style headers
    ARCNET_LINUX,
    /// Juniper-private data link type, as per request from Hannes Gredler <hannes@juniper.net>.
    /// The corresponding DLT_s are used for passing on chassis-internal metainformation such as
    /// QOS profiles, etc..
    JUNIPER_MLPPP,
    /// Juniper-private data link type, as per request from Hannes Gredler <hannes@juniper.net>.
    /// The corresponding DLT_s are used for passing on chassis-internal metainformation such as
    /// QOS profiles, etc..
    JUNIPER_MLFR,
    /// Juniper-private data link type, as per request from Hannes Gredler <hannes@juniper.net>.
    /// The corresponding DLT_s are used for passing on chassis-internal metainformation such as
    /// QOS profiles, etc..
    JUNIPER_ES,
    /// Juniper-private data link type, as per request from Hannes Gredler <hannes@juniper.net>.
    /// The corresponding DLT_s are used for passing on chassis-internal metainformation such as
    /// QOS profiles, etc..
    JUNIPER_GGSN,
    /// Juniper-private data link type, as per request from Hannes Gredler <hannes@juniper.net>.
    /// The corresponding DLT_s are used for passing on chassis-internal metainformation such as
    /// QOS profiles, etc..
    JUNIPER_MFR,
    /// Juniper-private data link type, as per request from Hannes Gredler <hannes@juniper.net>.
    /// The corresponding DLT_s are used for passing on chassis-internal metainformation such as
    /// QOS profiles, etc..
    JUNIPER_ATM2,
    /// Juniper-private data link type, as per request from Hannes Gredler <hannes@juniper.net>.
    /// The corresponding DLT_s are used for passing on chassis-internal metainformation such as
    /// QOS profiles, etc..
    JUNIPER_SERVICES,
    /// Juniper-private data link type, as per request from Hannes Gredler <hannes@juniper.net>.
    /// The corresponding DLT_s are used for passing on chassis-internal metainformation such as
    /// QOS profiles, etc..
    JUNIPER_ATM1,
    /// Apple IP-over-IEEE 1394 cooked header
    APPLE_IP_OVER_IEEE1394,
    /// ???
    MTP2_WITH_PHDR,
    /// ???
    MTP2,
    /// ???
    MTP3,
    /// ???
    SCCP,
    /// DOCSIS MAC frames
    DOCSIS,
    /// Linux-IrDA
    LINUX_IRDA,
    /// Reserved for IBM SP switch and IBM Next Federation switch.
    IBM_SP,
    /// Reserved for IBM SP switch and IBM Next Federation switch.
    IBM_SN,
    /// A link type we didn't recognise.
    Unknown(u16),
}

impl LinkType {
    /// Decode LinkType from u16
    pub fn from_u16(i: u16) -> LinkType {
        match i {
            0 => LinkType::NULL,
            1 => LinkType::ETHERNET,
            2 => LinkType::EXP_ETHERNET,
            3 => LinkType::AX24,
            4 => LinkType::PRONET,
            5 => LinkType::CHAOS,
            6 => LinkType::TOKEN_RING,
            7 => LinkType::ARCNET,
            8 => LinkType::SLIP,
            9 => LinkType::PPP,
            10 => LinkType::FDDI,
            50 => LinkType::PPP_HDLC,
            51 => LinkType::PPP_ETHER,
            99 => LinkType::SYMANTEC_FIREWALL,
            100 => LinkType::ATM_RFC1483,
            101 => LinkType::RAW,
            102 => LinkType::SLIP_BSDOS,
            103 => LinkType::PPP_BSDOS,
            104 => LinkType::C_HDLC,
            105 => LinkType::IEEE802_11,
            106 => LinkType::ATM_CLIP,
            107 => LinkType::FRELAY,
            108 => LinkType::LOOP,
            109 => LinkType::ENC,
            110 => LinkType::LANE8023,
            111 => LinkType::HIPPI,
            112 => LinkType::HDLC,
            113 => LinkType::LINUX_SLL,
            114 => LinkType::LTALK,
            115 => LinkType::ECONET,
            116 => LinkType::IPFILTER,
            117 => LinkType::PFLOG,
            118 => LinkType::CISCO_IOS,
            119 => LinkType::PRISM_HEADER,
            120 => LinkType::AIRONET_HEADER,
            121 => LinkType::HHDLC,
            122 => LinkType::IP_OVER_FC,
            123 => LinkType::SUNATM,
            124 => LinkType::RIO,
            125 => LinkType::PCI_EXP,
            126 => LinkType::AURORA,
            127 => LinkType::IEEE802_11_RADIO,
            128 => LinkType::TZSP,
            129 => LinkType::ARCNET_LINUX,
            130 => LinkType::JUNIPER_MLPPP,
            131 => LinkType::JUNIPER_MLFR,
            132 => LinkType::JUNIPER_ES,
            133 => LinkType::JUNIPER_GGSN,
            134 => LinkType::JUNIPER_MFR,
            135 => LinkType::JUNIPER_ATM2,
            136 => LinkType::JUNIPER_SERVICES,
            137 => LinkType::JUNIPER_ATM1,
            138 => LinkType::APPLE_IP_OVER_IEEE1394,
            139 => LinkType::MTP2_WITH_PHDR,
            140 => LinkType::MTP2,
            141 => LinkType::MTP3,
            142 => LinkType::SCCP,
            143 => LinkType::DOCSIS,
            144 => LinkType::LINUX_IRDA,
            145 => LinkType::IBM_SP,
            146 => LinkType::IBM_SN,
            // LINKTYPE_RAW is defined as 101 in the registry but for some reason libpcap uses DLT_RAW
            // defined as 14 on OpenBSD and as 12 for other platforms for the link type. So in order to
            // reliably decode link types we need to remap those numbers as LinkType::RAW here.
            12 => LinkType::RAW,
            14 => LinkType::RAW,
            x => LinkType::Unknown(x),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Copy)]
pub enum Endianness {
    Big,
    Little,
}

impl Endianness {
    pub fn parse_from_magic(buf: &[u8]) -> Result<Self> {
        let magic = &buf[0..4];
        match magic {
            [0x1A, 0x2B, 0x3C, 0x4D] => Ok(Endianness::Big),
            [0x4D, 0x3C, 0x2B, 0x1A] => Ok(Endianness::Little),
            _ => {
                let mut unknown_magic = [0; 4];
                unknown_magic.copy_from_slice(magic);
                Err(Error::DidntUnderstandMagicNumber(unknown_magic))
            }
        }
    }
}

pub trait KnownByteOrder {
    fn endianness() -> Endianness;
}

impl KnownByteOrder for BigEndian {
    fn endianness() -> Endianness {
        Endianness::Big
    }
}

impl KnownByteOrder for LittleEndian {
    fn endianness() -> Endianness {
        Endianness::Little
    }
}

/// The ID a network interface.
///
/// Note: Packets from different sections will have different interface IDs,
/// even if they were actually captured from the same interface.
#[derive(Clone, PartialEq, Eq, Debug, Copy)]
pub struct InterfaceId(pub u32);

pub trait FromBytes<'a>: Sized {
    fn parse<B: ByteOrder + KnownByteOrder>(buf: &'a [u8]) -> Result<Self>;
}

pub fn require_bytes(buf: &[u8], len: usize) -> Result<()> {
    if buf.len() < len {
        Err(Error::NotEnoughBytes {
            expected: len,
            actual: buf.len(),
        })
    } else {
        Ok(())
    }
}

/// A network interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interface {
    pub id: InterfaceId,
    pub link_type: LinkType,
    /// The if_tsresol option identifies the resolution of timestamps. If the Most Significant Bit
    /// is equal to zero, the remaining bits indicates the resolution of the timestamp as a negative
    /// power of 10 (e.g. 6 means microsecond resolution, timestamps are the number of microseconds
    /// since 1/1/1970). If the Most Significant Bit is equal to one, the remaining bits indicates
    /// the resolution as as negative power of 2 (e.g. 10 means 1/1024 of second). If this option is
    /// not present, a resolution of 10^-6 is assumed (i.e. timestamps have the same resolution of
    /// the standard 'libpcap' timestamps).
    pub units_per_sec: u32,
}

impl Interface {
    pub(crate) fn from_desc<B: ByteOrder>(
        id: InterfaceId,
        desc: &InterfaceDescription,
    ) -> Result<Interface> {
        let mut units_per_sec = 1_000_000;
        let mut i = 0;
        loop {
            if desc.options.len() < i + 4 {
                // no further options
                break;
            }
            let option_type = B::read_u16(&desc.options[i..i + 2]);
            i += 2;
            let option_len = B::read_u16(&desc.options[i..i + 2]) as usize;
            i += 2;
            match option_type {
                0 => {
                    // end of options
                    if i != desc.options.len() {
                        return Err(Error::OptionsAfterEnd);
                    }
                    break;
                }
                9 => {
                    // if_tsresol
                    if option_len != 1 {
                        return Err(Error::WrongOptionLen(option_len));
                    }
                    let v = desc.options[i];
                    let exp = u32::from(v & 0b0111_1111);
                    match v >> 7 {
                        0 => {
                            units_per_sec =
                                10_u32.checked_pow(exp).ok_or(Error::ResolutionTooHigh)?
                        }
                        1 => {
                            units_per_sec =
                                2_u32.checked_pow(exp).ok_or(Error::ResolutionTooHigh)?
                        }
                        _ => { /* impossible */ }
                    }
                }
                _ => { /* skip other option types */ }
            }
            let padding_len = (4 - option_len % 4) % 4;
            i += option_len + padding_len;
        }
        Ok(Interface {
            id,
            link_type: desc.link_type,
            units_per_sec,
        })
    }
}
