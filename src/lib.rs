/*!
pcarp is a pure-Rust library for reading pcap-ng files.

* _Correct_:  Agrees with `tshark` across a broad test suite.
* _Fast_:  Zero-copy.  Performance is comparable to `libpcap`.
* _Flexible input_:  Takes anything which implements `Read`.
* _Flexible output_: Exposes a streaming-iterator-style API.
* _Reliable_: No panics, even on malformed input.

See the README for more details.

The entry point is [`Capture`](struct.Capture.html).

## Example

```
# use pcarp::Capture;
# use std::time::*;
# use std::io::*;
# use std::fs::File;
let file = File::open("integration_tests/10_sqldeveloper10_2016.pcapng.xz").unwrap();
let uncompressed = xz2::read::XzDecoder::new(file);
let mut pcap = Capture::new(uncompressed).unwrap();

while let Some(pkt) = pcap.next() {
    let pkt = pkt.unwrap();
    println!("{:?} {}", pkt.timestamp, pkt.data.len());
}
```
*/

pub mod block;
pub mod iface;

use crate::block::*;
use crate::iface::{Interface, InterfaceId};
use buf_redux::policy::MinBuffered;
use buf_redux::BufReader;
use byteorder::{BigEndian, LittleEndian};
use std::io::{BufRead, Read, Seek, SeekFrom};
use std::ops::Range;
use std::result;
use std::time::*;
use thiserror::Error;
use tracing::*;

pub(crate) type Result<T, E = Error> = result::Result<T, E>;

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
    pub interface: Option<InterfaceId>,
    /// The raw packet data.
    pub data: &'a [u8],
    /// The location of the data in the underlying reader.
    pub data_offset: Range<usize>,
}

const BUF_CAPACITY: usize = 10_000_000;
const DEFAULT_MIN_BUFFERED: usize = 8 * 1024; // 8KB

/// A packet capture which can be iterated over.
///
/// There are two APIs here:
///
/// * Iterator style: `next`
/// * Streaming-iterator style: `advance`/`get`
///
/// The streaming iterator API is slightly more general when the items are
/// borrowed.  I expect that most users will just use `next()`, but users
/// needing to work around lifetime contraints may need to use `advance/get`.
/// Nothing bad will happen if you mix these two APIs.
pub struct Capture<R> {
    rdr: BufReader<R, MinBuffered>,
    n_bytes_read: usize,
    finished: bool,

    /// Endianness used in the current section. Each section can use a different endianness.
    endianness: Endianness,
    /// The interface map for the current section.
    interfaces: Vec<Interface>,
    /// The resolved names for the current section.
    resolved_names: Vec<NameResolution>,

    last_block_len: usize,

    // These are about the last packet that was decoded
    current_section: u32,
    current_timestamp: Option<u64>,
    // Relative to the current section.  This is an index into `interfaces`.
    current_interface: Option<u32>,
    current_data: Range<usize>,
}

impl<R: Read> Capture<R> {
    /// Create a new `Capture`.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(rdr: R) -> Result<Capture<R>> {
        let mut rdr = BufReader::with_capacity(BUF_CAPACITY, rdr)
            .set_policy(MinBuffered(DEFAULT_MIN_BUFFERED));
        let endianness = peek_for_shb(rdr.fill_buf()?)?.ok_or(Error::DidntStartWithSHB)?;
        Ok(Capture {
            rdr,
            n_bytes_read: 0,
            finished: false,

            endianness,
            interfaces: Vec::new(),
            resolved_names: Vec::new(),

            last_block_len: 0,
            current_section: 0,
            current_timestamp: None,
            current_interface: None,
            current_data: 0..0,
        })
    }

    /// Get the next packet.
    ///
    /// This function is a wrapper around the lower-level API:
    /// it simply calls `advance()` then `get()`.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<Result<Packet>> {
        match self.advance() {
            Err(e) => Some(Err(e)),
            Ok(()) => self.get().map(Ok),
        }
    }

    /// Parse the next packet from the pcap file.
    ///
    /// This function parses the packet but doesn't return it.  Use `get()`
    /// to see the results.
    pub fn advance(&mut self) -> Result<()> {
        loop {
            // Look at the length of the _last_ block, to see how much data to discard
            self.rdr.consume(self.last_block_len);
            self.n_bytes_read += self.last_block_len;

            // Fill the buffer up - hopefully we'll have enough data for the next block!
            let buf = self.rdr.fill_buf()?;
            if buf.is_empty() {
                self.last_block_len = 0;
                self.finished = true;
                return Ok(());
            }

            // We might have a new section coming up; in which case, change endianness.
            if let Some(endianness) = peek_for_shb(buf)? {
                trace!("Found SHB; setting endianness to {:?}", endianness);
                self.endianness = endianness;
            }

            // Parse the next block, and update the interface description map etc. if necessary.
            let (len, block) = match self.endianness {
                Endianness::Big => Block::parse::<BigEndian>(buf),
                Endianness::Little => Block::parse::<LittleEndian>(buf),
            };
            self.last_block_len = len;
            let block = block?;

            match block {
                Block::SectionHeader(x) => {
                    debug!("Starting a new section: {:?}", x);
                    assert_eq!(self.endianness, x.endianness);
                    self.interfaces.clear();
                    self.current_interface = None;
                    self.resolved_names.clear();
                    self.current_section += 1;
                }
                Block::InterfaceDescription(desc) => {
                    debug!("Defined a new interface: {:?}", desc);
                    if desc.snap_len > BUF_CAPACITY as u32 {
                        warn!(
                            "The max packet length for this interface is greater than the length of
                              our buffer."
                        );
                    }
                    let iface_id = InterfaceId(self.current_section, self.interfaces.len() as u32);
                    let iface = match self.endianness {
                        Endianness::Big => Interface::from_desc::<BigEndian>(iface_id, &desc)?,
                        Endianness::Little => {
                            Interface::from_desc::<LittleEndian>(iface_id, &desc)?
                        }
                    };
                    debug!("Parsed: {:?}", iface);
                    self.interfaces.push(iface);
                }
                Block::EnhancedPacket(pkt) => {
                    trace!("Got a packet: {:?}", pkt);
                    self.current_timestamp = Some(pkt.timestamp);
                    self.current_interface = Some(pkt.interface_id);
                    self.current_data = pkt.packet_data;
                    return Ok(());
                }
                Block::SimplePacket(pkt) => {
                    trace!("Got a packet: {:?}", pkt);
                    self.current_timestamp = None;
                    self.current_interface = None;
                    self.current_data = pkt.packet_data;
                    return Ok(());
                }
                Block::ObsoletePacket(pkt) => {
                    trace!("Got a packet: {:?}", pkt);
                    self.current_timestamp = Some(pkt.timestamp);
                    self.current_interface = Some(pkt.interface_id);
                    self.current_data = pkt.packet_data;
                    return Ok(());
                }
                Block::NameResolution(x) => {
                    debug!("Defined a new resolved name: {:?}", x);
                    self.resolved_names.push(x.clone());
                }
                Block::InterfaceStatistics(x) => {
                    debug!("Got some interface statistics: {:?}", x);
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

    /// Peek the current packet.
    ///
    /// This function is cheap, since `Packet` holds a reference to the
    /// internal buffer and no pcap data is copied.  When you're done with
    /// this packet and want to see the next one, use `advance()` to move on.
    pub fn get(&self) -> Option<Packet> {
        if self.finished {
            return None;
        }

        let interface = self
            .current_interface
            .map(|x| InterfaceId(self.current_section, x));

        let timestamp = self
            .current_interface
            .and_then(|id| self.interfaces.get(id as usize))
            .zip(self.current_timestamp)
            .map(|(iface, ts)| {
                let units_per_sec = u64::from(iface.units_per_sec);
                let secs = ts / units_per_sec;
                let nanos = ((ts % units_per_sec) * 1_000_000_000 / units_per_sec) as u32;
                SystemTime::UNIX_EPOCH + Duration::new(secs, nanos)
            });

        let body = &self.rdr.buffer()[8..];
        let data_offset = std::ops::Range {
            start: self.current_data.start + self.n_bytes_read + 8,
            end: self.current_data.end + self.n_bytes_read + 8,
        };
        let data = &body.get(self.current_data.clone())?;

        Some(Packet {
            timestamp,
            interface,
            data,
            data_offset,
        })
    }

    /// Get some info about a certain network interface.
    ///
    /// Note: Only shows info for the interfaces in the current section of
    /// the pcap.
    pub fn lookup_interface(&self, interface_id: InterfaceId) -> Option<&Interface> {
        if interface_id.0 != self.current_section {
            None
        } else {
            self.interfaces.get(interface_id.1 as usize)
        }
    }
}

impl<R: Read + Seek> Capture<R> {
    /// Rewind to the beginning of the pcapng file
    pub fn rewind(&mut self) -> Result<()> {
        self.rdr.seek(SeekFrom::Start(0))?;
        self.n_bytes_read = 0;
        self.finished = false;
        self.endianness = peek_for_shb(self.rdr.fill_buf()?)?.ok_or(Error::DidntStartWithSHB)?;
        self.interfaces = Vec::new();
        self.resolved_names = Vec::new();
        self.last_block_len = 0;
        self.current_timestamp = None;
        self.current_interface = None;
        self.current_data = 0..0;
        Ok(())
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
