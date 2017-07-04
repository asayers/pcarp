#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq)]
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
}

impl LinkType {
    pub fn from_u16(x: u16) -> Option<LinkType> {
        match x {
            000 => Some(LinkType::NULL),
            001 => Some(LinkType::ETHERNET),
            002 => Some(LinkType::EXP_ETHERNET),
            003 => Some(LinkType::AX24),
            004 => Some(LinkType::PRONET),
            005 => Some(LinkType::CHAOS),
            006 => Some(LinkType::TOKEN_RING),
            007 => Some(LinkType::ARCNET),
            008 => Some(LinkType::SLIP),
            009 => Some(LinkType::PPP),
            010 => Some(LinkType::FDDI),
            050 => Some(LinkType::PPP_HDLC),
            051 => Some(LinkType::PPP_ETHER),
            099 => Some(LinkType::SYMANTEC_FIREWALL),
            100 => Some(LinkType::ATM_RFC1483),
            101 => Some(LinkType::RAW),
            102 => Some(LinkType::SLIP_BSDOS),
            103 => Some(LinkType::PPP_BSDOS),
            104 => Some(LinkType::C_HDLC),
            105 => Some(LinkType::IEEE802_11),
            106 => Some(LinkType::ATM_CLIP),
            107 => Some(LinkType::FRELAY),
            108 => Some(LinkType::LOOP),
            109 => Some(LinkType::ENC),
            110 => Some(LinkType::LANE8023),
            111 => Some(LinkType::HIPPI),
            112 => Some(LinkType::HDLC),
            113 => Some(LinkType::LINUX_SLL),
            114 => Some(LinkType::LTALK),
            115 => Some(LinkType::ECONET),
            116 => Some(LinkType::IPFILTER),
            117 => Some(LinkType::PFLOG),
            118 => Some(LinkType::CISCO_IOS),
            119 => Some(LinkType::PRISM_HEADER),
            120 => Some(LinkType::AIRONET_HEADER),
            121 => Some(LinkType::HHDLC),
            122 => Some(LinkType::IP_OVER_FC),
            123 => Some(LinkType::SUNATM),
            124 => Some(LinkType::RIO),
            125 => Some(LinkType::PCI_EXP),
            126 => Some(LinkType::AURORA),
            127 => Some(LinkType::IEEE802_11_RADIO),
            128 => Some(LinkType::TZSP),
            129 => Some(LinkType::ARCNET_LINUX),
            130 => Some(LinkType::JUNIPER_MLPPP),
            131 => Some(LinkType::JUNIPER_MLFR),
            132 => Some(LinkType::JUNIPER_ES),
            133 => Some(LinkType::JUNIPER_GGSN),
            134 => Some(LinkType::JUNIPER_MFR),
            135 => Some(LinkType::JUNIPER_ATM2),
            136 => Some(LinkType::JUNIPER_SERVICES),
            137 => Some(LinkType::JUNIPER_ATM1),
            138 => Some(LinkType::APPLE_IP_OVER_IEEE1394),
            139 => Some(LinkType::MTP2_WITH_PHDR),
            140 => Some(LinkType::MTP2),
            141 => Some(LinkType::MTP3),
            142 => Some(LinkType::SCCP),
            143 => Some(LinkType::DOCSIS),
            144 => Some(LinkType::LINUX_IRDA),
            145 => Some(LinkType::IBM_SP),
            146 => Some(LinkType::IBM_SN),
            _   => None,
        }
    }
}
