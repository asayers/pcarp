use clap::App;
use log::*;
use pcarp::*;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::time::*;

fn main() {
    let args = App::new("pcap_dump")
        .version("0.1")
        .about("Dumps the packets from a pcapng file")
        .args_from_usage(
            "<pcap>  'The pcapng file to read from'
             --verbose -v 'Enable verbose output'",
        )
        .get_matches();

    // Initialise the logger
    let log_level = if args.is_present("verbose") {
        log::LevelFilter::Info
    } else {
        log::LevelFilter::Warn
    };
    env_logger::Builder::new().filter(None, log_level).init();

    let path = PathBuf::from(args.value_of("pcap").unwrap());
    let file = File::open(&path).unwrap();
    let reader: Box<Read> = match path.extension().unwrap().to_str().unwrap() {
        "pcapng" => Box::new(file),
        "gz" => Box::new(flate2::read::GzDecoder::new(file)),
        "xz" => Box::new(xz2::read::XzDecoder::new(file)),
        x => {
            warn!("Didn't recognise file extension {}; assuming plain pcap", x);
            Box::new(file)
        }
    };
    let mut pcap = Capture::new(reader).unwrap();

    let start = Instant::now();
    let mut n = 0;
    while let Some(pkt) = pcap.next() {
        let pkt = pkt.unwrap();
        n += 1;
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
}

fn sanitize(data: &[u8]) -> String {
    String::from_utf8_lossy(data).replace(|x: char| !x.is_ascii() || x.is_control(), ".")
}
