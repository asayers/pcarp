use internal::*;
use packet::*;
use std::u32;

pub struct Section {
    pub interfaces: Vec<InterfaceDescription>,
    pub resolved_names: Vec<NameResolution>,
}

impl Section {
    pub fn new() -> Section {
        Section {
            interfaces: Vec::new(),
            resolved_names: Vec::new(),
        }
    }

    pub fn handle_block<'a>(&'a mut self, block: Block<'a>) -> Option<Packet<'a>> {
        match block {
            Block::SectionHeader(x) => {
                info!("Starting a new section: {:?}", x);
                self.interfaces.clear();
                self.resolved_names.clear();
                None
            }
            Block::InterfaceDescription(x) => {
                info!("Defined a new interface: {:?}", x);
                if x.snap_len > BUF_CAPACITY as u32 {
                    warn!(
                        "The max packet length for this interface is greater than the length of
                          our buffer."
                    );
                }
                self.interfaces.push(x);
                None
            }
            Block::EnhancedPacket(x) => {
                debug!("Got a packet: {:?}", x);
                let interface = self.lookup_interface(x.interface_id);
                Some(Packet::new_enhanced(x.timestamp, interface, x.packet_data))
            }
            Block::SimplePacket(x) => {
                debug!("Got a packet: {:?}", x);
                Some(Packet::new_basic(x.packet_data))
            }
            Block::ObsoletePacket(x) => {
                debug!("Got a packet: {:?}", x);
                let interface = self.lookup_interface(x.interface_id);
                Some(Packet::new_enhanced(x.timestamp, interface, x.packet_data))
            }
            Block::NameResolution(x) => {
                info!("Defined a new resolved name: {:?}", x);
                self.resolved_names.push(x);
                None
            }
            Block::InterfaceStatistics(x) => {
                info!("Got some interface statistics: {:?}", x);
                None
            }
            Block::IRIGTimestamp => {
                warn!("IRIG timestamp blocks are ignored");
                None
            }
            Block::Arinc429 => {
                warn!("Arinc429 blocks are ignored");
                None
            }
        }
    }

    fn lookup_interface(&self, interface_id: InterfaceId) -> &InterfaceDescription {
        let interface_id = interface_id.0 as usize;
        assert!(
            interface_id < self.interfaces.len(),
            "Out of bounds: {:?}",
            interface_id
        );
        &self.interfaces[interface_id]
    }
}
