use bpaf::Bpaf;
use pcarp::Capture;
use std::{fs::File, path::PathBuf};

/// Example program that demonstrates the rewind support
#[derive(Bpaf)]
#[bpaf(options)]
struct Opts {
    /// The pcapng file to read from
    #[bpaf(positional)]
    pcap: PathBuf,
}

fn main() {
    let opts = opts().fallback_to_usage().run();
    env_logger::init();
    let file = File::open(&opts.pcap).unwrap();
    let mut capture = Capture::new(file);
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
