use bpaf::Bpaf;
use pcap::*;
use std::{path::PathBuf, time::*};
use tracing::*;

/// Dumps the packets from a pcapng file
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

    let mut pcap = Capture::from_file(opts.pcap).unwrap();
    let ts = Instant::now();
    let mut n = 0;
    loop {
        match pcap.next_packet() {
            Ok(pkt) => {
                n += 1;
                let dur = Duration::new(
                    pkt.header.ts.tv_sec as u64,
                    pkt.header.ts.tv_usec as u32 * 1000,
                );
                println!("{:?}", dur);
            }
            Err(Error::NoMorePackets) => {
                info!("EOF. Terminating");
                break;
            }
            Err(Error::PcapError(e)) => {
                eprintln!("{:?}", e);
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
