# pcarp

A pure-Rust library for reading pcap-ng files.

* _Correct_:  Produces the same results as `tshark` for all the pcapng
  files I could scrape from the [Wireshark wiki][1].  See
  [integration_tests/][3] for details.
* _Fast_:  `pcarp` is zero-copy.  Performance is comparable to `libpcap`.
  Actually, on some files `pcarp` consistently underperforms, and on
  some it consistently overperforms, so it's not really possible to say
  which of the two performs better;  but it's fair to say they're similar.
* _Flexible input_:  The input can be anything which implements `Read`.
  Are your pcaps gzipped?  No problem, just wrap your `File` in a
  [`GzDecoder`][2] before you feed it to `Capture::new()`.
* _Flexible output_:  The output API is streaming-iterator-style
  (`advance()` and `get()`), which is more general than iterator-style
  (`next()`) when the content is borrowed.  An iterator-style API is
  also included for convenience.
* _Reliable_:  None of the public API should panic, even given malformed
  input.  `pcarp` is fuzzed extensively to ensure that this is the case.
  (Note that, given pathological input, `pcarp` may give you an infinite
  series of errors.)

[1]: https://wiki.wireshark.org/SampleCaptures
[2]: https://docs.rs/flate2/*/flate2/read/struct.GzDecoder.html
[3]: integration_tests/

Limitations compared to `libpcap`:

* No support for legacy pcap;  `pcarp` is pcap-ng-only.
* No dissection of any kind.  `pcarp` gives you the raw packet data.
  If you want to parse ethernet/IP/TCP/whatever protocol, try [pnet] or
  [rshark].
* No filtering.  This one follows from "no dissection".

[pnet]: https://docs.rs/pnet
[rshark]: https://docs.rs/rshark

# License

The software itself is in the public domain.

Some of the documentation is copied from the pcap spec, so the copyright is
owned by the IETF;  these places are cleary marked.  The pcaps used by the
integration tests are distributed by the Wireshark Foundation under the terms
of the GNU GPL.
