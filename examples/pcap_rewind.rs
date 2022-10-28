use clap::Parser;
use pcarp::*;
use std::fs::File;
use std::path::PathBuf;

/// Example program that demonstrates the rewind support
#[derive(Parser)]
struct Opts {
    /// The pcapng file to read from
    pcap: PathBuf,
}

fn main() {
    let opts = Opts::parse();
    env_logger::init();
    let file = File::open(&opts.pcap).unwrap();
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
