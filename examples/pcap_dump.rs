use clap::Parser;
use pcarp::*;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::time::*;
use tracing::*;

/// Dumps the packets from a pcapng file
#[derive(Parser)]
struct Opts {
    /// The pcapng file to read from
    pcap: PathBuf,
}

fn main() {
    let opts = Opts::parse();

    env_logger::init();

    let file = File::open(&opts.pcap).unwrap();
    let reader: Box<dyn Read> = match opts.pcap.extension().and_then(|x| x.to_str()) {
        Some("pcapng") => Box::new(file),
        Some("gz") => Box::new(flate2::read::GzDecoder::new(file)),
        Some("xz") => Box::new(xz2::read::XzDecoder::new(file)),
        Some(x) => {
            warn!("Didn't recognise file extension {}; assuming plain pcap", x);
            Box::new(file)
        }
        None => {
            warn!("No file extension; assuming plain pcap");
            Box::new(file)
        }
    };
    let mut pcap = match Capture::new(reader) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    let start = Instant::now();
    for (n, pkt) in pcap.enumerate() {
        match pkt {
            Ok(pkt) => {
                let ts = pkt.timestamp.unwrap_or(SystemTime::UNIX_EPOCH);
                println!(
                    "[{}] {:>5}  {}",
                    humantime::format_rfc3339_nanos(ts),
                    pkt.data.len(),
                    sanitize(pkt.data)
                );
                if n % 1000 == 0 {
                    let nanos = start.elapsed().subsec_nanos();
                    let bps = f64::from(n) * 1_000_000_000.0 / f64::from(nanos);
                    info!("Read {} blocks at {} pps", n, bps);
                }
            }
            Err(e) => {
                eprintln!("{}", e);
            }
        }
    }
}

fn sanitize(data: &[u8]) -> String {
    String::from_utf8_lossy(data).replace(|x: char| !x.is_ascii() || x.is_control(), ".")
}
