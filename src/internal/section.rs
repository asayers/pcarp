use byteorder::{BigEndian, LittleEndian};
use internal::*;
use packet::*;
use std::u32;

#[derive(Clone, PartialEq, Debug)]
pub struct Section {
    /// Endianness used in the current section. Each section can use a different endianness.
    pub endianness: Endianness,
    pub interfaces: Vec<InterfaceDescription>,
    pub resolved_names: Vec<NameResolution>,
    /// Timestamp resolution for each interface in the current section.
    pub timestamp_options: Vec<TimestampOptions>,
}

impl Section {
    pub fn new() -> Section {
        Section {
            endianness: Endianness::Little, // arbitrary default
            interfaces: Vec::new(),
            resolved_names: Vec::new(),
            timestamp_options: Vec::new(),
        }
    }

    pub fn handle_block(&mut self, block: &Block) {
        match block {
            Block::SectionHeader(x) => {
                info!("Starting a new section: {:?}", x);
                self.endianness = x.endianness.clone();
                self.interfaces.clear();
                self.resolved_names.clear();
                self.timestamp_options.clear();
            }
            Block::InterfaceDescription(x) => {
                info!("Defined a new interface: {:?}", x);
                if x.snap_len > BUF_CAPACITY as u32 {
                    warn!(
                        "The max packet length for this interface is greater than the length of
                          our buffer."
                    );
                }
                match self.endianness {
                    Endianness::Big => self
                        .timestamp_options
                        .push(x.timestamp_options::<BigEndian>()),
                    Endianness::Little => self
                        .timestamp_options
                        .push(x.timestamp_options::<LittleEndian>()),
                }
                info!("Set the timestamp options to {:?}", self.timestamp_options);
                self.interfaces.push(x.clone());
            }
            Block::EnhancedPacket(_) => (),
            Block::SimplePacket(_) => (),
            Block::ObsoletePacket(_) => (),
            Block::NameResolution(x) => {
                info!("Defined a new resolved name: {:?}", x);
                self.resolved_names.push(x.clone());
            }
            Block::InterfaceStatistics(x) => {
                info!("Got some interface statistics: {:?}", x);
            }
            Block::IRIGTimestamp => {
                warn!("IRIG timestamp blocks are ignored");
            }
            Block::Arinc429 => {
                warn!("Arinc429 blocks are ignored");
            }
            Block::Unknown(n) => {
                warn!("Not handling unknown block: {}", n);
            }
        }
    }

    pub fn block_to_packet<'a>(&'a self, block: Block<'a>) -> Option<Packet<'a>> {
        match block {
            Block::SectionHeader(_) => None,
            Block::InterfaceDescription(_) => None,
            Block::EnhancedPacket(x) => {
                debug!("Got a packet: {:?}", x);
                let interface = self.lookup_interface(&x.interface_id);
                let timestamp_options = self.lookup_timestamp_options(&x.interface_id);
                Some(Packet::new_enhanced(
                    x.timestamp,
                    timestamp_options,
                    interface,
                    x.packet_data,
                ))
            }
            Block::SimplePacket(x) => {
                debug!("Got a packet: {:?}", x);
                Some(Packet::new_basic(x.packet_data))
            }
            Block::ObsoletePacket(x) => {
                debug!("Got a packet: {:?}", x);
                let interface = self.lookup_interface(&x.interface_id);
                let timestamp_options = self.lookup_timestamp_options(&x.interface_id);
                Some(Packet::new_enhanced(
                    x.timestamp,
                    timestamp_options,
                    interface,
                    x.packet_data,
                ))
            }
            Block::NameResolution(_) => None,
            Block::InterfaceStatistics(_) => None,
            Block::IRIGTimestamp => None,
            Block::Arinc429 => None,
            Block::Unknown(_) => None,
        }
    }

    fn lookup_interface(&self, interface_id: &InterfaceId) -> &InterfaceDescription {
        let interface_id = interface_id.0 as usize;
        assert!(
            interface_id < self.interfaces.len(),
            "Out of bounds: {:?}",
            interface_id
        );
        &self.interfaces[interface_id]
    }

    fn lookup_timestamp_options(&self, interface_id: &InterfaceId) -> &TimestampOptions {
        let interface_id = interface_id.0 as usize;
        assert!(
            interface_id < self.interfaces.len(),
            "Out of bounds: {:?}",
            interface_id
        );
        &self.timestamp_options[interface_id]
    }
}

impl Default for Section {
    fn default() -> Self {
        Self::new()
    }
}
