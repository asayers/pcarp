#!/bin/bash -eu

RUSTFLAGS="-Clink-arg=-fuse-ld=gold" cargo afl build

# Generate the corpus
mkdir full
for i in ../integration_tests/*.pcapng.xz; do
    unxz < $i > "full/$(basename -s.xz $i)"
done
RUSTFLAGS="-Clink-arg=-fuse-ld=gold" cargo afl build
find full -size +10k | xargs rm
rm -r corpus 2>/dev/null || true
cargo afl cmin -i full -o corpus target/debug/fuzz
rm -r full

# And fuzz
cargo afl fuzz -i corpus -o out target/debug/fuzz
