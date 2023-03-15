/*! Info and stats about the network interfaces used to capture packets */

use crate::block::{InterfaceDescription, InterfaceStatistics, Timestamp};
use std::fmt;
use std::time::{Duration, SystemTime};

/// The type of physical link backing a network interface
///
/// You can find the lastest list [here][reference].
///
/// [reference]: https://github.com/IETF-OPSAWG-WG/draft-ietf-opsawg-pcap/blob/master/linktypes.csv
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

/// The ID a network interface.
///
/// Note: Packets from different sections will have different interface IDs,
/// even if they were actually captured from the same interface.
#[derive(Clone, PartialEq, Eq, Debug, Copy)]
pub struct InterfaceId(pub u32, pub u32);

/// A network interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceInfo {
    pub(crate) descr: InterfaceDescription,
    pub(crate) stats: Option<InterfaceStatistics>,
}

impl InterfaceInfo {
    pub(crate) fn resolve_ts(&self, ts: Timestamp) -> SystemTime {
        let units_per_sec = u64::from(self.descr.if_tsresol);
        let secs = ts.0 / units_per_sec;
        let nanos = ((ts.0 % units_per_sec) * 1_000_000_000 / units_per_sec) as u32;
        SystemTime::UNIX_EPOCH + Duration::new(secs, nanos)
    }
}

impl InterfaceInfo {
    pub fn link_type(&self) -> LinkType {
        self.descr.link_type
    }

    pub fn snap_len(&self) -> Option<u32> {
        self.descr.snap_len
    }

    pub fn name(&self) -> &str {
        &self.descr.if_name
    }

    pub fn description(&self) -> &str {
        &self.descr.if_description
    }

    // TODO: Fix type
    pub fn ipv4_addrs(&self) -> &[[u8; 8]] {
        &self.descr.if_ipv4_addr
    }

    // TODO: Fix type
    pub fn ipv6_addrs(&self) -> &[[u8; 17]] {
        &self.descr.if_ipv6_addr
    }

    // TODO: Fix type
    pub fn mac_addr(&self) -> Option<[u8; 6]> {
        self.descr.if_mac_addr
    }

    // TODO: Fix type
    pub fn eui_addr(&self) -> Option<[u8; 8]> {
        self.descr.if_eui_addr
    }

    pub fn speed(&self) -> Option<u64> {
        self.descr.if_speed
    }

    // TODO: Fix type
    pub fn tzone(&self) -> Option<[u8; 4]> {
        self.descr.if_tzone
    }

    pub fn filter(&self) -> &str {
        &self.descr.if_filter
    }

    pub fn os(&self) -> &str {
        &self.descr.if_os
    }

    // TODO: Fix type
    pub fn fcslen(&self) -> Option<[u8; 1]> {
        self.descr.if_fcslen
    }

    // TODO: Fix type
    pub fn tsoffset(&self) -> Option<[u8; 8]> {
        self.descr.if_tsoffset
    }

    pub fn hardware(&self) -> &str {
        &self.descr.if_hardware
    }

    // TODO: Fix type
    pub fn txspeed(&self) -> Option<[u8; 8]> {
        self.descr.if_txspeed
    }

    // TODO: Fix type
    pub fn rxspeed(&self) -> Option<[u8; 8]> {
        self.descr.if_rxspeed
    }

    pub fn stats_timestamp(&self) -> Option<SystemTime> {
        self.stats
            .as_ref()
            .map(|stats| self.resolve_ts(stats.timestamp))
    }

    pub fn starttime(&self) -> Option<SystemTime> {
        self.stats
            .as_ref()
            .and_then(|stats| stats.isb_starttime)
            .map(|ts| self.resolve_ts(ts))
    }

    pub fn endtime(&self) -> Option<SystemTime> {
        self.stats
            .as_ref()
            .and_then(|stats| stats.isb_endtime)
            .map(|ts| self.resolve_ts(ts))
    }

    pub fn ifrecv(&self) -> Option<u64> {
        self.stats.as_ref().and_then(|stats| stats.isb_ifrecv)
    }

    pub fn ifdrop(&self) -> Option<u64> {
        self.stats.as_ref().and_then(|stats| stats.isb_ifdrop)
    }

    pub fn filter_accept(&self) -> Option<u64> {
        self.stats
            .as_ref()
            .and_then(|stats| stats.isb_filter_accept)
    }

    pub fn osdrop(&self) -> Option<u64> {
        self.stats.as_ref().and_then(|stats| stats.isb_osdrop)
    }

    pub fn usrdeliv(&self) -> Option<u64> {
        self.stats.as_ref().and_then(|stats| stats.isb_usrdeliv)
    }
}

impl fmt::Display for InterfaceInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{} ({})", self.name(), self.description())?;
        if !self.filter().is_empty() {
            writeln!(f, "filter: {}", self.filter())?;
        }
        if !self.os().is_empty() {
            writeln!(f, "OS: {}", self.os())?;
        }
        if !self.hardware().is_empty() {
            writeln!(f, "hardware: {}", self.hardware())?;
        }
        if self.ipv4_addrs().len() + self.ipv6_addrs().len() > 0 {
            writeln!(
                f,
                "ip addrs: {:?} {:?}",
                self.ipv4_addrs(),
                self.ipv6_addrs(),
            )?;
        }
        if let Some(x) = self.mac_addr() {
            writeln!(f, "MAC addr: {x:?}")?;
        }
        if let Some(x) = self.eui_addr() {
            writeln!(f, "EUI addr: {x:?}")?;
        }
        if let Some(x) = self.speed() {
            writeln!(f, "speed: {x}")?;
        }
        if let Some(x) = self.tzone() {
            writeln!(f, "tzone: {x:?}")?;
        }
        if let Some(x) = self.fcslen() {
            writeln!(f, "fcslen: {x:?}")?;
        }
        if let Some(x) = self.tsoffset() {
            writeln!(f, "tsoffset: {x:?}")?;
        }
        if let Some(x) = self.txspeed() {
            writeln!(f, "txspeed: {x:?}")?;
        }
        if let Some(x) = self.rxspeed() {
            writeln!(f, "rxspeed: {x:?}")?;
        }
        if let Some(x) = self.stats_timestamp() {
            writeln!(f, "stats_timestamp: {x:?}")?; // humantime::Timestamp::from(x)
        }
        if let Some(x) = self.starttime() {
            writeln!(f, "starttime: {x:?}")?; // humantime::Timestamp::from(x)
        }
        if let Some(x) = self.endtime() {
            writeln!(f, "endtime: {x:?}")?; // humantime::Timestamp::from(x)
        }
        if let Some(x) = self.ifrecv() {
            writeln!(f, "ifrecv: {x}")?;
        }
        if let Some(x) = self.ifdrop() {
            writeln!(f, "ifdrop: {x}")?;
        }
        if let Some(x) = self.filter_accept() {
            writeln!(f, "filter_accept: {x}")?;
        }
        if let Some(x) = self.osdrop() {
            writeln!(f, "osdrop: {x}")?;
        }
        if let Some(x) = self.usrdeliv() {
            writeln!(f, "usrdeliv: {x}")?;
        }
        Ok(())
    }
}
