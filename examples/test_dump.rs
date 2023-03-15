use pcarp::*;
use std::os::unix::fs::FileExt;

fn main() {
    env_logger::init();
    let path = std::path::PathBuf::from(std::env::args().nth(1).unwrap());
    let file = std::fs::File::open(&path).unwrap();
    let pcap = Capture::new(file);
    let file = std::fs::File::open(&path).unwrap();
    let mut buf = vec![0; 1024 * 1024];
    for pkt in pcap {
        let pkt = pkt.unwrap();
        let ts = pkt
            .timestamp
            .unwrap();
        let n_bytes = pkt.data_offset.end - pkt.data_offset.start;
        file.read_exact_at(&mut buf[..n_bytes], pkt.data_offset.start as u64)
            .unwrap();
        assert_eq!(pkt.data, &buf[..n_bytes]);
        println!(
            "{}\t{:x}",
            humantime::Timestamp::from(ts),
            md5::compute(pkt.data),
        );
    }
}
