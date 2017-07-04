use blocks::*;
use byteorder::{ByteOrder, BigEndian, LittleEndian};
use link_type::*;
use std::time::Duration;
use types::*;

pub struct Section {
    pub header: Option<SectionHeader>,
    pub interfaces: Vec<InterfaceDescription>,
}

impl Section {
    pub fn new() -> Section {
        Section {
            header: None,
            interfaces: Vec::new(),
        }
    }

    pub fn handle_block<'a>(&mut self, block: Block<'a>) -> Option<Packet<'a>> {
        match block {
            Block::SectionHeader(x) => { self.header = Some(x); None }
            Block::InterfaceDescription(x) => { self.interfaces.push(x); None }
            Block::EnhancedPacket(x) => { Some(self.enhanced_packet(x)) }
            Block::SimplePacket(x) => { None }
            Block::ObsoletePacket(x) => { None }
            Block::NameResolution(x) => { None }
            Block::InterfaceStatistics(x) => { None }
            Block::IRIGTimestamp => { debug!("IRIG timestamp blocks are ignored"); None }
            Block::Arinc429 => { debug!("Arinc429 blocks are ignored"); None }
        }
    }

    fn enhanced_packet<'a>(&self, x: EnhancedPacket<'a>) -> Packet<'a> {
        let interface = self.lookup_interface(x.interface_id).unwrap();
        Packet {
            timestamp: assemble_timestamp(interface, x.timestamp_high, x.timestamp_low),
            link_type: LinkType::from_u16(interface.link_type).unwrap(),
            snap_len: interface.snap_len,
            data: x.packet_data,
        }
    }

    fn lookup_interface(&self, interface_id: u32) -> Option<&InterfaceDescription> {
        let interface_id = interface_id as usize;
        if interface_id < self.interfaces.len() {
            Some(&self.interfaces[interface_id])
        } else {
            None
        }
    }
}

pub struct Packet<'a> {
    pub timestamp: Duration,
    pub link_type: LinkType,
    pub snap_len: u32,
    pub data: &'a[u8],
}

fn assemble_timestamp(interface: &InterfaceDescription, ts_high: u32, ts_low: u32) -> Duration {
    // TODO: Get resolution from InterfaceDescription by inspecting if_tsresol
    let resolution = 10_000_000;   // assume microsecond resolution (FIXME)
    Duration::from_millis(1)
}
