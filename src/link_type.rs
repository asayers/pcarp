#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, FromPrimitive)]
#[repr(u16)]
pub enum LinkType {
    /// No link layer information. A packet saved with this link layer contains a raw L3 packet
    /// preceded by a 32-bit host-byte-order AF_ value indicating the specific L3 type.
    NULL = 000,
    /// D/I/X and 802.3 Ethernet
    ETHERNET = 001,
    /// Experimental Ethernet (3Mb)
    EXP_ETHERNET = 002,
    /// Amateur Radio AX.25
    AX24 = 003,
    /// Proteon ProNET Token Ring
    PRONET = 004,
    /// Chaos
    CHAOS = 005,
    /// IEEE 802 Networks
    TOKEN_RING = 006,
    /// ARCNET, with BSD-style header
    ARCNET = 007,
    /// Serial Line IP
    SLIP = 008,
    /// Point-to-point Protocol
    PPP = 009,
    /// FDDI
    FDDI = 010,
    /// PPP in HDLC-like framing
    PPP_HDLC = 050,
    /// NetBSD PPP-over-Ethernet
    PPP_ETHER = 051,
    /// Symantec Enterprise Firewall
    SYMANTEC_FIREWALL = 099,
    /// LLC/SNAP-encapsulated ATM
    ATM_RFC1483 = 100,
    /// Raw IP
    RAW = 101,
    /// BSD/OS SLIP BPF header
    SLIP_BSDOS = 102,
    /// BSD/OS PPP BPF header
    PPP_BSDOS = 103,
    /// Cisco HDLC
    C_HDLC = 104,
    /// IEEE 802.11 (wireless)
    IEEE802_11 = 105,
    /// Linux Classical IP over ATM
    ATM_CLIP = 106,
    /// Frame Relay
    FRELAY = 107,
    /// OpenBSD loopback
    LOOP = 108,
    /// OpenBSD IPSEC enc
    ENC = 109,
    /// ATM LANE + 802.3 (Reserved for future use)
    LANE8023 = 110,
    /// NetBSD HIPPI (Reserved for future use)
    HIPPI = 111,
    /// NetBSD HDLC framing (Reserved for future use)
    HDLC = 112,
    /// Linux cooked socket capture
    LINUX_SLL = 113,
    /// Apple LocalTalk hardware
    LTALK = 114,
    /// Acorn Econet
    ECONET = 115,
    /// Reserved for use with OpenBSD ipfilter
    IPFILTER = 116,
    /// OpenBSD DLT_PFLOG
    PFLOG = 117,
    /// For Cisco-internal use
    CISCO_IOS = 118,
    /// 802.11+Prism II monitor mode
    PRISM_HEADER = 119,
    /// FreeBSD Aironet driver stuff
    AIRONET_HEADER = 120,
    /// Reserved for Siemens HiPath HDLC
    HHDLC = 121,
    /// RFC 2625 IP-over-Fibre Channel
    IP_OVER_FC = 122,
    /// Solaris+SunATM
    SUNATM = 123,
    /// RapidIO - Reserved as per request from Kent Dahlgren <kent@praesum.com> for private use.
    RIO = 124,
    /// PCI Express - Reserved as per request from Kent Dahlgren <kent@praesum.com> for private
    /// use.
    PCI_EXP = 125,
    /// Xilinx Aurora link layer - Reserved as per request from Kent Dahlgren <kent@praesum.com>
    /// for private use.
    AURORA = 126,
    /// 802.11 plus BSD radio header
    IEEE802_11_RADIO = 127,
    /// Tazmen Sniffer Protocol - Reserved for the TZSP encapsulation, as per request from Chris
    /// Waters <chris.waters@networkchemistry.com> TZSP is a generic encapsulation for any other
    /// link type, which includes a means to include meta-information with the packet, e.g. signal
    /// strength and channel for 802.11 packets.
    TZSP = 128,
    /// Linux-style headers
    ARCNET_LINUX = 129,
    /// Juniper-private data link type, as per request from Hannes Gredler <hannes@juniper.net>.
    /// The corresponding DLT_s are used for passing on chassis-internal metainformation such as
    /// QOS profiles, etc..
    JUNIPER_MLPPP = 130,
    /// Juniper-private data link type, as per request from Hannes Gredler <hannes@juniper.net>.
    /// The corresponding DLT_s are used for passing on chassis-internal metainformation such as
    /// QOS profiles, etc..
    JUNIPER_MLFR = 131,
    /// Juniper-private data link type, as per request from Hannes Gredler <hannes@juniper.net>.
    /// The corresponding DLT_s are used for passing on chassis-internal metainformation such as
    /// QOS profiles, etc..
    JUNIPER_ES = 132,
    /// Juniper-private data link type, as per request from Hannes Gredler <hannes@juniper.net>.
    /// The corresponding DLT_s are used for passing on chassis-internal metainformation such as
    /// QOS profiles, etc..
    JUNIPER_GGSN = 133,
    /// Juniper-private data link type, as per request from Hannes Gredler <hannes@juniper.net>.
    /// The corresponding DLT_s are used for passing on chassis-internal metainformation such as
    /// QOS profiles, etc..
    JUNIPER_MFR = 134,
    /// Juniper-private data link type, as per request from Hannes Gredler <hannes@juniper.net>.
    /// The corresponding DLT_s are used for passing on chassis-internal metainformation such as
    /// QOS profiles, etc..
    JUNIPER_ATM2 = 135,
    /// Juniper-private data link type, as per request from Hannes Gredler <hannes@juniper.net>.
    /// The corresponding DLT_s are used for passing on chassis-internal metainformation such as
    /// QOS profiles, etc..
    JUNIPER_SERVICES = 136,
    /// Juniper-private data link type, as per request from Hannes Gredler <hannes@juniper.net>.
    /// The corresponding DLT_s are used for passing on chassis-internal metainformation such as
    /// QOS profiles, etc..
    JUNIPER_ATM1 = 137,
    /// Apple IP-over-IEEE 1394 cooked header
    APPLE_IP_OVER_IEEE1394 = 138,
    /// ???
    MTP2_WITH_PHDR = 139,
    /// ???
    MTP2 = 140,
    /// ???
    MTP3 = 141,
    /// ???
    SCCP = 142,
    /// DOCSIS MAC frames
    DOCSIS = 143,
    /// Linux-IrDA
    LINUX_IRDA = 144,
    /// Reserved for IBM SP switch and IBM Next Federation switch.
    IBM_SP = 145,
    /// Reserved for IBM SP switch and IBM Next Federation switch.
    IBM_SN = 146,
}
