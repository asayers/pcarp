#!/usr/bin/env bash
set -eu
cargo build --release --examples
for pcapxz in ./integration_tests/*.pcapng.xz; do
    name=$(basename -s .pcapng.xz $pcapxz)
    pcap=$(mktemp)
    echo "Benchmarking $name..."
    pixz -d <$pcapxz >$pcap
    timeout --preserve-status 5 \
        cbdr sample \
            "pcarp:target/release/examples/simple_dump pcarp $pcap" \
            "libpcap:target/release/examples/simple_dump libpcap $pcap" |
            cbdr analyze
done
