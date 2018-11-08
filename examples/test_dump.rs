extern crate pcarp;
extern crate sha1;
extern crate xz2;

use pcarp::*;

fn main() {
    let path = std::path::PathBuf::from(std::env::args().nth(1).unwrap());
    let file = std::fs::File::open(&path).unwrap();
    let mut pcap = Pcapng::new(xz2::read::XzDecoder::new(file)).unwrap();
    while let Some(pkt) = pcap.next() {
        let pkt = pkt.unwrap();
        let ts = pkt
            .timestamp
            .unwrap()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap();
        println!(
            "{:0>10}.{:0>9} {:>6} {}",
            ts.as_secs(),
            ts.subsec_nanos(),
            pkt.data.len(),
            sha1::Sha1::from(pkt.data).hexdigest()
        );
    }
}
