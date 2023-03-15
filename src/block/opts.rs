use crate::block::util::*;
use bytes::{Buf, Bytes};
use tracing::*;

pub(crate) fn parse_options<T: Buf>(
    mut buf: T,
    endianness: Endianness,
    mut handle: impl FnMut(u16, Bytes),
) {
    while buf.remaining() > 3 {
        let option_type = read_u16(&mut buf, endianness);
        let option_len = read_u16(&mut buf, endianness);
        let option_bytes = match read_bytes(&mut buf, option_len as u32) {
            Ok(x) => x,
            Err(_) => {
                warn!(
                    "Saw a truncated option.  Not going to try to parse any \
                    more options"
                );
                break;
            }
        };
        match option_type {
            // The opt_endofopt option delimits the end of the optional
            // fields. This option MUST NOT be repeated within a given
            // list of options.
            0 => {
                if option_len != 0 {
                    warn!("The end-of-opt option contained a payload: {option_bytes:?}");
                }
                break;
            }
            // The opt_comment option is a UTF-8 string containing
            // human-readable comment text that is associated to the
            // current block. Line separators SHOULD be a carriage-return
            // + linefeed ('\r\n') or just linefeed ('\n'); either form
            // may appear and be considered a line separator. The string
            // is not zero-terminated.
            1 => (), // We don't do anything with comments; discard
            // References to the "custom data" section of the pcap.
            // We don't handle any of this stuff.
            2988 | 2989 | 19372 | 19373 => (),
            // Block-specific or custom
            _ => handle(option_type, option_bytes),
        }
    }
    if buf.remaining() != 0 {
        warn!(
            "The block contained extra bytes after the options: {:?}",
            buf.copy_to_bytes(buf.remaining()),
        );
    }
}

pub(crate) fn bytes_to_string(bytes: Bytes) -> String {
    String::from_utf8_lossy(&bytes).to_string()
}

pub(crate) fn ensure_len(bytes: &Bytes, expected: usize) -> Option<()> {
    let actual = bytes.len();
    if expected == actual {
        Some(())
    } else {
        warn!(
            "Option has the wrong length: expected {expected} bytes but \
            saw {actual}"
        );
        None
    }
}

pub(crate) fn bytes_to_array<const N: usize>(bytes: Bytes) -> Option<[u8; N]> {
    ensure_len(&bytes, N)?;
    bytes.as_ref().try_into().ok()
}

pub(crate) fn bytes_to_u64(mut bytes: Bytes, endianness: Endianness) -> Option<u64> {
    ensure_len(&bytes, 8)?;
    Some(read_u64(&mut bytes, endianness))
}

pub(crate) fn bytes_to_u32(mut bytes: Bytes, endianness: Endianness) -> Option<u32> {
    ensure_len(&bytes, 4)?;
    Some(read_u32(&mut bytes, endianness))
}

pub(crate) fn bytes_to_ts(mut bytes: Bytes, endianness: Endianness) -> Option<Timestamp> {
    ensure_len(&bytes, 8)?;
    Some(read_ts(&mut bytes, endianness))
}
