extern crate clap;
extern crate env_logger;
#[macro_use]
extern crate log;
extern crate flate2;
extern crate pcarp;
extern crate xz2;

use clap::App;
use pcarp::*;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::thread;
use std::time::*;

fn main() {
    let args = App::new("pcap_dump")
        .version("0.1")
        .about("Dumps the packets from a pcapng file")
        .args_from_usage(
            "<pcap>  'The pcapng file to read from'
             --verbose -v 'Enable verbose output'",
        ).get_matches();

    // Initialise the logger
    let log_level = if args.is_present("verbose") {
        log::LevelFilter::Info
    } else {
        log::LevelFilter::Warn
    };
    env_logger::Builder::new().filter(None, log_level).init();

    let path = PathBuf::from(args.value_of("pcap").unwrap());
    let file = File::open(&path).unwrap();
    let reader: Box<Read> = match path.extension().and_then(|x| x.to_str()) {
        Some("pcapng") => Box::new(file),
        Some("gz") => Box::new(flate2::read::GzDecoder::new(file)),
        Some("xz") => Box::new(xz2::read::XzDecoder::new(file)),
        None => panic!("not a file"),
        Some(x) => panic!("Didn't recognise file extension {}; skipping", x),
    };
    let mut pcap = Pcapng::new(reader).unwrap();

    let ts = Instant::now();
    let mut n = 0;
    loop {
        match pcap.next() {
            Ok(Some(pkt)) => {
                n += 1;
                println!("{}", pkt);
            }
            Ok(None) => { /* the block was not a packet */ }
            Err(Error::NotEnoughBytes { expected, actual }) => {
                warn!(
                    "Not enough bytes ({}/{}); sleeping and retrying.",
                    actual, expected
                );
                thread::sleep(Duration::from_millis(500));
            }
            Err(Error::ZeroBytes) => {
                info!("EOF. Terminating");
                break;
            }
            Err(e) => {
                panic!("{:?}", e);
            }
        }
        if n % 1000 == 0 {
            let nanos = ts.elapsed().subsec_nanos();
            let bps = f64::from(n) * 1_000_000_000.0 / f64::from(nanos);
            info!("Read {} blocks at {} pps", n, bps);
        }
    }
}
