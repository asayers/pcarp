use pcap::*;
use std::fs::File;
use std::time::*;

fn main() {
    let mut args = std::env::args();
    let _ = args.next();
    let backend = args.next().unwrap();
    let path = args.next().unwrap();
    match backend.as_str() {
        "pcarp" => {
            let file = File::open(&path).unwrap();
            let mut pcap = pcarp::Capture::new(file).unwrap();
            for pkt in pcap {
                match pkt {
                    Ok(pkt) => {
                        let ts = pkt.timestamp.unwrap_or(SystemTime::UNIX_EPOCH);
                        println!("{:?}", ts);
                    }
                    Err(e) => panic!("{}", e),
                }
            }
        }
        "libpcap" => {
            let mut pcap = Capture::from_file(path).unwrap();
            loop {
                match pcap.next_packet() {
                    Ok(pkt) => {
                        let ts = SystemTime::UNIX_EPOCH
                            + Duration::new(
                                pkt.header.ts.tv_sec as u64,
                                pkt.header.ts.tv_usec as u32 * 1000,
                            );
                        println!("{:?}", ts);
                    }
                    Err(Error::NoMorePackets) => break,
                    Err(Error::PcapError(_)) => (),
                    Err(e) => panic!("{}", e),
                }
            }
        }
        x => panic!("Unknown: {}", x),
    }
}
