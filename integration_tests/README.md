This directory contains "golden" tests.  We have a bunch of pcapng files, and
for each we have a plain-text dump of its contents.  These text files have one
line per packet, formatted like so:

    <timestamp> <data MD5>

The `test_dump` example program outputs the same format.  `run.sh` is a script
which generates ".actual" files using `test_dump` and compares them to their
corresponding ".expected" file.  You will need to have `unxz` installed.

# License

The capture files in this directory were scraped from the [Wireshark wiki][1],
where they seem to be distributed under the terms of the GNU GPL (see
[here][2]).  I'm not exactly sure how the GPL applies to pcap files...

[1]: https://wiki.wireshark.org/SampleCaptures
[2]: https://wiki.wireshark.org/License

# Generating expected results

I generated the ".expected" files using the following ugly script:

    #!/bin/bash -eu

    # For each packet in the given capture file, this function will print the
    # length and SHA1 of the packet's data on a separate line.
    pkt_checksums() {
        tshark -r "$1" -x |
            # Clean up the hexdump by removing the byte numbers and ascii. Also,
            # sometimes tshark outputs "reassembled packets" - we don't want those.
            # Finally, we group each packet's hexdump into a single line.
            gawk 'BEGIN {ignore=0}
                  /^$/{ print acc; acc=""; ignore=0 }
                  match($0, /[0-9a-f]{4}  (([0-9a-f]{2} )+)  .*/, a) { if (!ignore) acc = acc a[1] }
                  /^Reassembled.*/ {ignore=1}' |
            while read -r x; do
                # unhex and take the checksum
                cksum=$(echo "$x" | xxd -r -p | sha1sum | cut -d' ' -f1)
                len=$(echo "$x" | xxd -r -p | wc -c)
                printf "%6s %s\n" "$len" "$cksum"
            done
    }

    timestamps() {
        # Left-padding with zeros is surprisingly ugly - don't look!
        # Also, it doesn't quite work properly
        tshark -te -r "$1" | awk '{
            split($2, a, ".");
            if (length(a[2] < 9))
                printf("%10d.%s%0" 9-length(a[2]) "d\n", a[1], a[2], 0)
            else
                printf("%10d.%s\n", a[1], a[2])
        }'
    }

    for i in *.pcapng; do
        o=${i/pcapng/expected}
        echo "Generating $o..."
        paste -d' ' <(timestamps "$i") <(pkt_checksums "$i") > "$o"
    done
