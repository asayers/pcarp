use pcarp::*;
use sha1::{Digest, Sha1};
use std::os::unix::fs::FileExt;

fn main() {
    env_logger::init();
    let path = std::path::PathBuf::from(std::env::args().nth(1).unwrap());
    let file = std::fs::File::open(&path).unwrap();
    let mut pcap = Capture::new(file).unwrap();
    let file = std::fs::File::open(&path).unwrap();
    let mut buf = vec![0; 1024 * 1024];
    while let Some(pkt) = pcap.next() {
        let pkt = pkt.unwrap();
        let ts = pkt
            .timestamp
            .unwrap()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap();
        let n_bytes = pkt.data_offset.end - pkt.data_offset.start;
        file.read_exact_at(&mut buf[..n_bytes], pkt.data_offset.start as u64)
            .unwrap();
        assert_eq!(pkt.data, &buf[..n_bytes]);
        println!(
            "{:0>10}.{:0>9} {:>6} {:x}",
            ts.as_secs(),
            ts.subsec_nanos(),
            pkt.data.len(),
            Sha1::digest(pkt.data),
        );
    }
}
