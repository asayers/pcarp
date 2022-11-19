use pcarp::*;
use sha1::{Digest, Sha1};

fn main() {
    env_logger::init();
    let path = std::path::PathBuf::from(std::env::args().nth(1).unwrap());
    let file = std::fs::File::open(&path).unwrap();
    let mut pcap = Capture::new(file).unwrap();
    while let Some(pkt) = pcap.next() {
        let pkt = pkt.unwrap();
        let ts = pkt
            .timestamp
            .unwrap()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap();
        println!(
            "{:0>10}.{:0>9} {:>6} {:x}",
            ts.as_secs(),
            ts.subsec_nanos(),
            pkt.data.len(),
            Sha1::digest(pkt.data),
        );
    }
}
