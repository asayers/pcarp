use internal::*;
use std::fmt::{self, Display, Formatter};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub struct Packet<'a> {
    pub timestamp: Option<Duration>,
    pub interface: Option<&'a InterfaceDescription>,
    pub data: &'a [u8],
}

impl<'a> Packet<'a> {
    pub fn new_basic(data: &[u8]) -> Packet {
        Packet {
            timestamp: None,
            interface: None,
            data,
        }
    }

    pub fn new_enhanced(
        timestamp: u64,
        timestamp_options: &'a TimestampOptions,
        interface: &'a InterfaceDescription,
        data: &'a [u8],
    ) -> Packet<'a> {
        let units_per_sec = u64::from(timestamp_options.units_per_sec);
        let secs = timestamp / units_per_sec;
        let nanos = ((timestamp % units_per_sec) * 1_000_000_000 / units_per_sec) as u32;
        Packet {
            timestamp: Some(Duration::new(secs, nanos)),
            interface: Some(interface),
            data,
        }
    }
}

impl<'a> Display for Packet<'a> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self.timestamp {
            Some(x) => write!(f, "{}.{:0>9}\t", x.as_secs(), x.subsec_nanos())?,
            None => write!(f, "unknown\t")?,
        }
        match self.interface {
            Some(x) => write!(f, "{:?}\t", x.link_type)?,
            None => write!(f, "unknown\t")?,
        }
        write!(
            f,
            "{}",
            String::from_utf8_lossy(self.data)
                .replace(|x: char| !x.is_ascii() || x.is_control(), ".")
        )
    }
}
