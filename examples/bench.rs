extern crate pcap;
extern crate pcarp;

use pcap::Capture;
use pcarp::Pcapng;
use std::fs::File;
use std::path::Path;
use std::time::*;

fn main() {
    let path = Path::new("test_data/foo.pcapng");
    run_both(&path);
    run_pcapng(&path);
    run_libpcap(&path);
}

fn run_both(path: &Path) {
    let file = File::open(path).unwrap();
    let mut pcap1 = Pcapng::new(file).unwrap();
    let mut pcap2 = Capture::from_file(path).unwrap();
    let mut n = 0;
    loop {
        n += 1;
        let p2 = pcap2.next().unwrap();
        loop {
            match pcap1.next() {
                Ok(Some(p1)) => {
                    if p1.data == p2.data {
                        println!("yeah {}", n);
                    } else {
                        println!("nooo!");
                    }
                    break;
                }
                Ok(None) => {}
                Err(pcarp::Error::NotEnoughBytes { expected, actual }) => {
                    println!("waiting {}/{}", actual, expected);
                }
                e => panic!("{:?}", e),
            }
        }
    }
}

fn run_pcapng(path: &Path) {
    let file = File::open(path).unwrap();
    let mut pcap = Pcapng::new(file).unwrap();
    let ts = Instant::now();
    let mut n: u64 = 0;
    loop {
        match pcap.next() {
            Ok(Some(_)) => {
                n += 1;
            }
            Ok(None) => { /* the block was not a packet */ }
            Err(pcarp::Error::NotEnoughBytes { .. }) => break,
            Err(pcarp::Error::ZeroBytes) => break,
            Err(e) => {
                panic!("{:?}", e);
            }
        }
    }
    let nanos = ts.elapsed().subsec_nanos();
    let secs = nanos as f64 / 1_000_000_000.0;
    let bps = n as f64 / secs;
    println!("Read {} packets at {} pps", n, bps);
}

fn run_libpcap(path: &Path) {
    let mut pcap = Capture::from_file(path).unwrap();
    let ts = Instant::now();
    let mut n: u64 = 0;
    loop {
        match pcap.next() {
            Ok(_) => {
                n += 1;
            }
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => {
                panic!("{:?}", e);
            }
        }
    }
    let nanos = ts.elapsed().subsec_nanos();
    let secs = nanos as f64 / 1_000_000_000.0;
    let bps = n as f64 / secs;
    println!("Read {} packets at {} pps", n, bps);
}
