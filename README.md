# pcarp

A pure-Rust library for reading pcap-ng files.

* _Correct_:  Produces the same results as `tshark` for all the pcapng files I
  could scrape from the [Wireshark wiki][1].  See [integration_tests/][3] for
  details.
* _Fast_:  About 4x faster than `libpcap`.  A representative benchmark shows
  `pcarp` hitting 8.9M pkt/s, 2 GB/s, while `libpcap` gets 1.9 pkt/s, 0.5 GB/s
  on the same file.
* _Flexible_:  Takes anything which implements `Read` as input.  Are your pcaps
  compressed?  No problem, just wrap them in a [`GzDecoder`][2].

[1]: https://wiki.wireshark.org/SampleCaptures
[2]: https://docs.rs/flate2/*/flate2/read/struct.GzDecoder.html
[3]: integration_tests/

# License

The software itself is in the public domain.

Some of the documentation is copied from the pcap spec, so the copyright is
owned by the IETF;  these places are cleary marked.  The pcaps used by the
integration tests are distributed by the Wireshark Foundation under the terms
of the GNU GPL.
