/*!
pcarp is pure-Rust library for reading pcap-ng files.

* _Correct_:  Agrees with `tshark` across a broad test suite.
* _Fast_:  Performance is comparable to `libpcap`;  YMMV.
* _Flexible_:  Takes anything which implements `Read`;  returns packets with a
  streaming-iterator-style API.

```
# use pcarp::Pcapng;
# use std::time::*;
# use std::io::*;
# use std::fs::File;
let file = File::open("integration_tests/10_sqldeveloper10_2016.pcapng.xz").unwrap();
let uncompressed = xz2::read::XzDecoder::new(file);
let mut pcap = Pcapng::new(uncompressed).unwrap();
while let Some(pkt) = pcap.next() {
    let pkt = pkt.unwrap();
    let ts = pkt.timestamp.unwrap_or(Duration::from_secs(0));
    println!("[{:?}] Packet with length {}", ts, pkt.data.len());
}
```
*/

extern crate buf_redux;
extern crate byteorder;
#[macro_use]
extern crate log;
#[macro_use]
extern crate failure;

pub mod block;
mod types;

use block::*;
use buf_redux::policy::MinBuffered;
use buf_redux::BufReader;
use byteorder::{BigEndian, LittleEndian};
use std::io::{BufRead, Read};
use std::ops::Range;
use std::time::Duration;
use types::*;
pub use types::{Error, Interface, LinkType, Packet};

const BUF_CAPACITY: usize = 10_000_000;

pub struct Pcapng<R> {
    rdr: BufReader<R, MinBuffered>,
    finished: bool,

    /// Endianness used in the current section. Each section can use a different endianness.
    endianness: Endianness,
    /// The interface map for the current section.
    interfaces: Vec<Interface>,
    /// The resolved names for the current section.
    resolved_names: Vec<NameResolution>,

    last_block_len: usize,

    // These are about the last packet that was decoded
    current_timestamp: Option<u64>,
    current_interface: Option<InterfaceId>,
    current_data: Range<usize>,
}

const DEFAULT_MIN_BUFFERED: usize = 8 * 1024; // 8KB

impl<R: Read> Pcapng<R> {
    /// Create a new `Pcapng`.
    pub fn new(rdr: R) -> Result<Pcapng<R>> {
        Self::with_capacity(rdr, BUF_CAPACITY)
    }

    fn with_capacity(rdr: R, cap: usize) -> Result<Pcapng<R>> {
        let mut rdr =
            BufReader::with_capacity(cap, rdr).set_policy(MinBuffered(DEFAULT_MIN_BUFFERED));
        let endianness = peek_for_shb(rdr.fill_buf()?)?.ok_or(Error::DidntStartWithSHB)?;
        Ok(Pcapng {
            rdr,
            finished: false,

            endianness,
            interfaces: Vec::new(),
            resolved_names: Vec::new(),

            last_block_len: 0,
            current_timestamp: None,
            current_interface: None,
            current_data: 0..0,
        })
    }

    /// Get the next packet
    pub fn next<'a, 'b>(&'a mut self) -> Option<Result<Packet<'b>>>
    where
        'a: 'b,
    {
        match self.advance() {
            Err(e) => Some(Err(e)),
            Ok(()) => self.get().map(Ok),
        }
    }

    pub fn advance(&mut self) -> Result<()> {
        loop {
            // Look at the length of the _last_ block, to see how much data to discard
            self.rdr.consume(self.last_block_len);

            // Fill the buffer up - hopefully we'll have enough data for the next block!
            let buf = self.rdr.fill_buf()?;
            if buf.is_empty() {
                self.last_block_len = 0;
                self.finished = true;
                return Ok(());
            }

            // We might have a new section coming up; in which case, change endianness.
            if let Some(endianness) = peek_for_shb(buf)? {
                debug!("Found SHB; setting endianness to {:?}", endianness);
                self.endianness = endianness;
            }

            // Parse the next block, and update the interface description map etc. if necessary.
            let (len, block) = match self.endianness {
                Endianness::Big => Block::parse::<BigEndian>(buf)?,
                Endianness::Little => Block::parse::<LittleEndian>(buf)?,
            };
            self.last_block_len = len;

            match block {
                Block::SectionHeader(x) => {
                    info!("Starting a new section: {:?}", x);
                    assert_eq!(self.endianness, x.endianness);
                    self.interfaces.clear();
                    self.resolved_names.clear();
                }
                Block::InterfaceDescription(desc) => {
                    info!("Defined a new interface: {:?}", desc);
                    if desc.snap_len > BUF_CAPACITY as u32 {
                        warn!(
                            "The max packet length for this interface is greater than the length of
                              our buffer."
                        );
                    }
                    let iface = match self.endianness {
                        Endianness::Big => Interface::from_desc::<BigEndian>(&desc),
                        Endianness::Little => Interface::from_desc::<LittleEndian>(&desc),
                    };
                    info!("Parsed: {:?}", iface);
                    self.interfaces.push(iface);
                }
                Block::EnhancedPacket(pkt) => {
                    debug!("Got a packet: {:?}", pkt);
                    self.current_timestamp = Some(pkt.timestamp);
                    self.current_interface = Some(pkt.interface_id);
                    self.current_data = pkt.packet_data;
                    return Ok(());
                }
                Block::SimplePacket(pkt) => {
                    debug!("Got a packet: {:?}", pkt);
                    self.current_timestamp = None;
                    self.current_interface = None;
                    self.current_data = pkt.packet_data;
                    return Ok(());
                }
                Block::ObsoletePacket(pkt) => {
                    debug!("Got a packet: {:?}", pkt);
                    self.current_timestamp = Some(pkt.timestamp);
                    self.current_interface = Some(pkt.interface_id);
                    self.current_data = pkt.packet_data;
                    return Ok(());
                }
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
    }

    pub fn get(&self) -> Option<Packet> {
        if self.finished {
            return None;
        }
        let interface = self.current_interface.map(|x| self.lookup_interface(x));
        let timestamp = self.current_interface.and_then(|i| {
            self.current_timestamp
                .map(|ts| self.resolve_timestamp(i, ts))
        });
        let body = &self.rdr.buffer()[8..];
        Some(Packet {
            timestamp,
            interface,
            data: &body[self.current_data.clone()],
        })
    }

    fn lookup_interface(&self, interface_id: InterfaceId) -> &Interface {
        &self.interfaces[interface_id.0 as usize]
    }

    fn resolve_timestamp(&self, interface_id: InterfaceId, timestamp: u64) -> Duration {
        let iface = self.lookup_interface(interface_id);
        let units_per_sec = u64::from(iface.units_per_sec);
        let secs = timestamp / units_per_sec;
        let nanos = ((timestamp % units_per_sec) * 1_000_000_000 / units_per_sec) as u32;
        Duration::new(secs, nanos)
    }
}

/// First we just need to check if it's an SHB, and set the endinanness if it is. This function
/// doesn't consume anything from the buffer, it just peeks.
fn peek_for_shb(buf: &[u8]) -> Result<Option<Endianness>> {
    require_bytes(buf, 4)?;
    let block_type = &buf[..4];
    if block_type != [0x0A, 0x0D, 0x0D, 0x0A] {
        return Ok(None);
    }
    require_bytes(buf, 12)?;
    let endianness = Endianness::parse_from_magic(&buf[8..12])?;
    Ok(Some(endianness))
}
