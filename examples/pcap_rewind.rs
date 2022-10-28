use clap::App;
use pcarp::*;
use std::fs::File;
use std::path::PathBuf;

fn main() {
    let args = App::new("pcap_rewind")
        .about("Example program that demonstrates the rewind support")
        .args_from_usage("<pcap> 'The pcapng file to read from'")
        .get_matches();

    env_logger::init();
    let path = PathBuf::from(args.value_of("pcap").unwrap());
    let file = File::open(&path).unwrap();
    let mut capture = Capture::new(file).unwrap();
    for _ in 0..3 {
        let pkt = capture.next().unwrap();
        println!("{:?}", pkt);
    }
    println!("-- rewind --");
    capture.rewind().unwrap();
    for _ in 0..3 {
        let pkt = capture.next().unwrap();
        println!("{:?}", pkt);
    }
}
