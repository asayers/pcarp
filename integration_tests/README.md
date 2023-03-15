The integration test suite consists of all the pcapng files I could scrape
from the [Wireshark wiki][wiki].  This directory contains those pcapng files,
along with a plain-text dump of its contents (suffixed with ".expected").
These text-dump files are formatted like so, with one line per packet:

    <timestamp> <data MD5>

The `test_dump` example program reads a pcap using pcarp and outputs the
same textual format.  `run.sh` runs `test_dump` on the pcaps (the output is
saved with a ".actual" suffix) and compares the two text files.

`run.sh` requires `unxz` to be installed.  If the expected file is missing,
`run.sh` will create it; for this it requires `tshark` to be installed.

[wiki]: https://wiki.wireshark.org/SampleCaptures

# License

The capture files in this directory were scraped from the [Wireshark wiki][1],
where they seem to be distributed under the terms of the GNU GPL (see
[here][2]).  I'm not exactly sure how the GPL applies to pcap files...

[1]: https://wiki.wireshark.org/SampleCaptures
[2]: https://wiki.wireshark.org/License
