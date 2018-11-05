#!/bin/bash -eu

YELLOW='\033[0;33m'
GREEN='\033[1;32m'
RED='\033[1;31m'
RESET='\033[0m'

runtest() {
    STDOUT=$(mktemp) &&
    cargo run --quiet --example=test_dump -- "$1" >"$STDOUT" &&
    diff --side-by-side "$STDOUT" "$i.expected"
}

cargo build --example=test_dump
ret=0
for i in $(dirname "$0")/data/*.pcapng.xz; do
    echo -ne "${YELLOW}Testing${RESET} ${i}... "
    OUT=$(mktemp)
    if runtest "$i" &>"$OUT"; then
        echo -e "${GREEN}OK${RESET}"
    else
        ret=$?
        echo -e "${RED}failed${RESET}"
        cat "$OUT"
    fi
done
exit $ret
