## Unreleased
* Refuse to parse legacy pcap format with a clearer error message

## 2.0.0

* Make `Packet` fully owned (no lifetime parameter)
* Change `Capture` from a streaming iterator into a normal iterator
* Make `Capture::new()` infallible
* Carefully distinguish between fatal and non-fatal errors
* Expose a bunch of new info about the capture interface

## 1.4.0

* Ensure interface IDs are unique within a pcap
* Expose the byte offset of the packet data within the pcap

## 1.3.0

* Expose the interface ID for each packet
* Expose the timestamp resolution for each interface
* Use the "tracing" crate for logging

## 1.2.0

* Simplify the lifetime of `Capture::next()`

## 1.1.0

* Implement `std::error::Error` for `Error`

## 1.0.0

* Fix a bunch of bugs caught by the fuzzer
