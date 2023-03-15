# pcarp

A pure-Rust library for reading pcapng files.

* _Correct_:   Agrees with `tshark` across a [broad test suite][integration_tests/].
* _Fast_:      Performance is similar to `libpcap`.
* _Flexible_:  Wraps anything which implements `Read`.
* _Ergonomic_: It's an iterator of `Packet`s - no lifetimes.
* _Resilient_: Handles malformed pcaps as gracefully as possible.

## Limitations

`libpcap` is full of features; `pcarp` just reads packets out of pcapng files.
Limitations compared to `libpcap`:

* No support for legacy pcap;  `pcarp` is pcapng-only.
* No support for writing; `pcarp` is read-only.
* No dissection of any kind.  `pcarp` gives you the raw packet data.
* No filtering.  This one follows from "no dissection".

If you want to parse ethernet/IP/TCP/whatever protocol, you need another
library.  We use [etherparse] and it works well.  There's also [pnet] or
[rshark], although I haven't tried them.

[etherparse]: https://docs.rs/etherparse
[pnet]: https://docs.rs/pnet
[rshark]: https://docs.rs/rshark

## Error handling

`pcarp` is designed to be very resilient to errors, even given malformed or
malicious input.

* If pcarp sees unexpected flags or options, it will log a warning using the
  `tracing` crate and carry on.
* If a packet is mangled beyond recognition, pcarp will return an error
  instead, but subsequent packets will still be readable.
* If pcarp encounters corruption in the framing, then the error is not
  containable, and no more packets can be read.

pcarp should _never_ panic.  It's fuzzed to help ensure that this is
the case, but fuzzing isn't perfect.  If you experience a crash, please
report it!

# License

The software itself is in the public domain.

Some of the documentation is copied from the pcap spec, so the copyright is
owned by the IETF;  these places are cleary marked.  The pcaps used by the
integration tests are distributed by the Wireshark Foundation under the terms
of the GNU GPL.
