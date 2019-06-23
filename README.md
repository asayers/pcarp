# pcarp

A pure-Rust library for reading pcap-ng files.

* _Correct_:  Agrees with `tshark` across a broad test suite.
* _Fast_:  Zero-copy.  Performance is comparable to `libpcap`.
* _Flexible input_:  Takes anything which implements `Read`.
* _Flexible output_: Exposes a streaming-iterator-style API.
* _Reliable_: No panics, even on malformed input.

## Limitations

`pcarp` is a simple library: it reads pcap-ng files and that's it.
Limitations compared to `libpcap`:

* No support for legacy pcap;  `pcarp` is pcap-ng-only.
* No support for writing; `pcarp` is read-only.
* No dissection of any kind.  `pcarp` gives you the raw packet data.
  If you want to parse ethernet/IP/TCP/whatever protocol, try [pnet] or
  [rshark].
* No filtering.  This one follows from "no dissection".

[pnet]: https://docs.rs/pnet
[rshark]: https://docs.rs/rshark

## API

Are your pcaps gzipped?  No problem: `Capture::new()` takes anything which
implements `Read`, so just wrap your `File` in a [`GzDecoder`][2] first.

The output API is streaming-iterator-style (`advance()` and `get()`), and
an iterator-style API is also included for convenience.

## Conformance

The integration test suite consists of all the pcapng files I could scrape
from the [Wireshark wiki][1].  See [integration_tests/][3] for details.

## Safety

It's our intention that `pcarp` should never panic, even given malformed or
malicious input.  The library is fuzzed to help ensure that this is the case,
but fuzzing isn't perfect.  If you experience a crash, please report it to
the authors.

It's currently possible to construct bad blocks which `pcarp` can't move past.
In other words: you can insert one of these malformed blocks into an otherwise
good pcap and instead of reporting a single error and moving on, `pcarp`
will give you an infinite series of errors.  If your input is untrusted,
don't assume that your stream will terminate.

## Performance

Proper benchmarking is a TODO.  I have compared the decoding time to
that of the `pcap` library (which uses `libpcap`) over a variety of pcaps.
On some files `pcarp` consistently overperforms, and on some it consistently
underperforms, so it's not really possible to say which of the two performs
better; but I think it's fair to say they're similar.

[1]: https://wiki.wireshark.org/SampleCaptures
[2]: https://docs.rs/flate2/*/flate2/read/struct.GzDecoder.html
[3]: integration_tests/

# License

The software itself is in the public domain.

Some of the documentation is copied from the pcap spec, so the copyright is
owned by the IETF;  these places are cleary marked.  The pcaps used by the
integration tests are distributed by the Wireshark Foundation under the terms
of the GNU GPL.
