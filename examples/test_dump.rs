use pcarp::*;

fn main() {
    env_logger::init();
    let path = std::path::PathBuf::from(std::env::args().nth(1).unwrap());
    let file = std::fs::File::open(&path).unwrap();
    let pcap = Capture::new(file);
    let process = |pkt: Result<Packet, Error>| -> Result<(), Box<dyn std::error::Error>> {
        let pkt = pkt?;
        let ts = pkt.timestamp.ok_or("No timestamp")?;
        println!(
            "{}\t{:x}",
            humantime::Timestamp::from(ts),
            md5::compute(&pkt.data),
        );
        Ok(())
    };
    for pkt in pcap {
        if let Err(e) = process(pkt) {
            eprintln!("{e}");
        }
    }
}
