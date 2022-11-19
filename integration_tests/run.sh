#!/bin/bash -eu

YELLOW='\033[0;33m'
GREEN='\033[1;32m'
RED='\033[1;31m'
RESET='\033[0m'

runtest() {
    cargo run --quiet --example=test_dump -- "$1" >"$1.actual" &&
    diff "$1.actual" "$1.expected" >/dev/null
}

cargo build --example=test_dump
ret=0
for i in $(dirname "$0")/*.pcapng.xz; do
    pcap=${i%%.xz}
    if ! [ -f "$pcap" ]; then
        unxz <$i >$pcap
    fi
    echo -ne "${YELLOW}Testing${RESET} ${pcap}... "
    if runtest "$pcap"; then
        echo -e "${GREEN}OK${RESET}"
    else
        ret=$?
        echo -e "${RED}failed${RESET}"
    fi
done
exit $ret
