use internal::*;
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
