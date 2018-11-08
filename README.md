# pcarp

A pure-Rust library for reading pcap-ng files.

* _Correct_:  Produces the same results as `tshark` for all the pcapng files I
  could scrape from the [Wireshark wiki][1].  See [integration_tests/][3] for
  details.
* _Fast_:  Performance is comparable to `libpcap`.  Actually, on some files
  `pcarp` consistently underperforms, and on some it consistently overperforms,
  so it's not really possible to say which of the two performs better;  but
  it's fair to say they're similar.
* _Flexible_:  The input can be anything which implements `Read` as input.  Are
  your pcaps compressed?  No problem, just wrap your `File` in a
  [`GzDecoder`][2] before you pass it to `Capture::new`.
* _Flexible_ (again):  The output API is streaming-iterator-style  (`advance`
  and `get`), which is more general than iterator-style (`next`) when the
  content is borrowed.

[1]: https://wiki.wireshark.org/SampleCaptures
[2]: https://docs.rs/flate2/*/flate2/read/struct.GzDecoder.html
[3]: integration_tests/

# License

The software itself is in the public domain.

Some of the documentation is copied from the pcap spec, so the copyright is
owned by the IETF;  these places are cleary marked.  The pcaps used by the
integration tests are distributed by the Wireshark Foundation under the terms
of the GNU GPL.
