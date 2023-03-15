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

use crate::block::{Block, BlockError, BlockReader, BlockType, FrameError, NameResolution};
use crate::iface::{InterfaceId, InterfaceInfo};
use bytes::Bytes;
use std::{
    io::{Read, Seek},
    time::SystemTime,
};
use thiserror::Error;
use tracing::*;

pub(crate) type Result<T, E = Error> = std::result::Result<T, E>;

/// An error; may be fatal or non-fatal
///
/// * If pcarp sees unexpected flags or options, it will log a warning using
///   the `tracing` crate and carry on.
/// * If a packet is mangled beyond recognition, pcarp will return a
///   [`BlockError`].  Subsequent packets will still be readable.
/// * If the pcap's framing is corrupt, pcarp will return a [`FrameError`].
///   Such errors can't be contained to a single packet, so we're finished.
///   If pcarp returns a `FrameError`, then further calls to `next()` will
///   return `None`.
/// * If the underlying reader returns an IO error, pcarp will forward
///   the error.  Such errors are not necessarily fatal (eg. `EAGAIN`),
///   but they may be (eg. `ECONNABORTED`).  In any case, the `Capture`
///   remains useable after returning an IO error, and calling `next()` will
///   re-attempt the read.  Depending on the error, it may succeed this time;
///   or it may simply trigger the same error again.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Error while parsing a frame (fatal)")]
    Frame(#[from] FrameError),
    #[error("Error while parsing a {0:?} block (non-fatal)")]
    Block(BlockType, #[source] BlockError),
    #[error("IO error")]
    IO(#[from] std::io::Error),
}

/// A captured packet
///
/// The pcapng spec defines three kinds of packets
/// ([`SimplePacket`][crate::block::SimplePacket],
/// [`EnhancedPacket`][crate::block::EnhancedPacket], and
/// [`ObsoletePacket`][crate::block::ObsoletePacket]).  This type provides
/// a unified view which can represent any of these three.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// The time at which the packet was captured.  The resolution depends on the interface.
    pub timestamp: Option<SystemTime>,
    /// The interface used to capture this packet.
    pub interface: Option<InterfaceId>,
    /// The raw packet data.
    pub data: Bytes,
}

/// An iterator that reads packets from a pcap
pub struct Capture<R> {
    inner: BlockReader<R>,
    current_section: u32,
    /// The interface map for the current section.  A `None` entry indicates
    /// that the interface definition block was mangled.
    interfaces: Vec<Option<InterfaceInfo>>,
    /// The resolved names for the current section.
    resolved_names: Vec<NameResolution>,
}

impl<R: Read> Capture<R> {
    /// Create a new `Capture`.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(rdr: R) -> Result<Capture<R>> {
        Ok(Capture {
            inner: BlockReader::new(rdr),
            current_section: 0,
            interfaces: Vec::new(),
            resolved_names: Vec::new(),
        })
    }

    /// Rewind to the beginning of the pcapng file
    pub fn rewind(&mut self) -> Result<()>
    where
        R: Seek,
    {
        self.inner.rewind()?;
        self.interfaces.clear();
        self.resolved_names.clear();
        Ok(())
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

impl<R: Read> Iterator for Capture<R> {
    type Item = Result<Packet>;
    fn next(&mut self) -> Option<Self::Item> {
        self.try_next().transpose()
    }
}

impl<R: Read> Capture<R> {
    /// Get the next packet
    fn try_next(&mut self) -> Result<Option<Packet>> {
        loop {
            let block = match self.inner.try_next() {
                Ok(Some(block)) => block,
                Ok(None) => return Ok(None),
                Err(e) => {
                    if let Error::Block(block_type, _) = e {
                        // This error is non-fatal, so let's try to handle
                        // it as best we can
                        self.handle_corrupt_block(block_type);
                    }
                    return Err(e);
                }
            };
            self.handle_block(&block);
            let Some((meta, data)) = block.into_pkt() else { continue };

            let interface = meta.map(|(_, iface)| InterfaceId(self.current_section, iface));
            let timestamp = meta.and_then(|(ts, iface)| {
                let iface = self.interfaces.get(iface as usize)?.as_ref()?;
                Some(iface.resolve_ts(ts))
            });

            return Ok(Some(Packet {
                timestamp,
                interface,
                data,
            }));
        }
    }

    fn start_new_section(&mut self) {
        self.interfaces.clear();
        self.resolved_names.clear();
        self.current_section += 1;
        debug!("Starting new section (#{})", self.current_section);
    }

    /// Update the interface description map etc. if necessary
    fn handle_block(&mut self, block: &Block) {
        match block {
            Block::SectionHeader(_) => self.start_new_section(),
            Block::InterfaceDescription(descr) => {
                debug!("Defined a new interface: {:?}", descr);
                if descr.snap_len.unwrap_or(0) > BlockReader::<R>::BUF_CAPACITY as u32 {
                    warn!(
                        "The max packet length for this interface is greater \
                        than the length of our buffer."
                    );
                }
                let iface = InterfaceInfo {
                    descr: descr.clone(),
                    stats: None,
                };
                debug!("Parsed: {iface:?}");
                self.interfaces.push(Some(iface));
            }
            Block::NameResolution(x) => {
                debug!("Defined a new resolved name: {x:?}");
                self.resolved_names.push(x.clone());
            }
            Block::InterfaceStatistics(stats) => {
                debug!("Got some interface statistics: {stats:?}");
                match self
                    .interfaces
                    .get_mut(stats.interface_id as usize)
                    .and_then(|x| x.as_mut())
                {
                    Some(x) => x.stats = Some(stats.clone()),
                    None => warn!("Saw statistics for an undefined interface"),
                }
            }
            Block::EnhancedPacket(pkt) => trace!("Got a packet: {pkt:?}"),
            Block::SimplePacket(pkt) => trace!("Got a packet: {pkt:?}"),
            Block::ObsoletePacket(pkt) => trace!("Got a packet: {pkt:?}"),
            Block::Unparsed(block_type) => {
                warn!("{block_type:?} blocks are ignored")
            }
        }
    }

    fn handle_corrupt_block(&mut self, block_type: BlockType) {
        use crate::block::BlockType as BT;
        match block_type {
            BT::SectionHeader => self.start_new_section(),
            BT::InterfaceDescription => self.interfaces.push(None),
            BT::NameResolution | BT::InterfaceStatistics => (),
            BT::ObsoletePacket | BT::SimplePacket | BT::EnhancedPacket => (),
            _ => (),
        }
    }
}
