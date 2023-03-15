use std::time::*;

fn main() {
    let path = std::path::PathBuf::from(std::env::args().nth(1).unwrap());
    let file = std::fs::File::open(&path).unwrap();
    let mut pcap = pcarp::Capture::new(file).unwrap();
    let mut n1 = 0;
    let mut bytes1 = 0;
    let start = Instant::now();
    for pkt in pcap {
        let pkt = pkt.unwrap();
        n1 += 1;
        bytes1 += pkt.data.len();
    }
    let t1 = start.elapsed();

    let mut pcap = pcap::Capture::from_file(&path).unwrap();
    let mut n2 = 0;
    let mut bytes2 = 0;
    let start = Instant::now();
    loop {
        match pcap.next_packet() {
            Err(pcap::Error::NoMorePackets) => break,
            Err(_) => (),
            Ok(pkt) => {
                n2 += 1;
                bytes2 += pkt.data.len();
            }
        }
    }
    let t2 = start.elapsed();

    assert_eq!(n1, n2);
    assert_eq!(bytes1, bytes2);

    let x = 2.0 * (t1.subsec_nanos() as f64 - t2.subsec_nanos() as f64)
        / (t1.subsec_nanos() + t2.subsec_nanos()) as f64;
    println!("{}", x);
}
