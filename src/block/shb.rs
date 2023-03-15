use crate::block::opts::*;
use crate::block::util::*;
use bytes::Buf;
use tracing::*;

/// Defines the most important characteristics of the capture file.
///
/// The Section Header Block (SHB) is mandatory. It identifies the beginning of a section of the
/// capture capture file. The Section Header Block does not contain data but it rather identifies a
/// list of blocks (interfaces, packets) that are logically correlated.
///
/// This documentation is copyright (c) 2018 IETF Trust and the persons identified as the
/// authors of [this document][1]. All rights reserved. Please see the linked document for the full
/// copyright notice.
///
/// [1]: https://github.com/pcapng/pcapng
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SectionHeader {
    /// Used to distinguish sections that have been saved on little-endian machines from the ones
    /// saved on big-endian machines.
    pub endianness: Endianness,
    /// Number of the current mayor version of the format. Current value is 1. This value should
    /// change if the format changes in such a way that code that reads the new format could not
    /// read the old format (i.e., code to read both formats would have to check the version number
    /// and use different code paths for the two formats) and code that reads the old format could
    /// not read the new format.
    pub major_version: u16,
    /// Number of the current minor version of the format. Current value is 0. This value should
    /// change if the format changes in such a way that code that reads the new format could read
    /// the old format without checking the version number but code that reads the old format could
    /// not read all files in the new format.
    pub minor_version: u16,
    /// A signed 64-bit value specifying the length in octets of the following section, excluding
    /// the Section Header Block itself. This field can be used to skip the section, for faster
    /// navigation inside large files. Section Length equal -1 (0xFFFFFFFFFFFFFFFF) means that the
    /// size of the section is not specified, and the only way to skip the section is to parse the
    /// blocks that it contains. Please note that if this field is valid (i.e. not negative), its
    /// value is always aligned to 32 bits, as all the blocks are aligned to and padded to 32-bit
    /// boundaries. Also, special care should be taken in accessing this field: since the alignment
    /// of all the blocks in the file is 32-bits, this field is not guaranteed to be aligned to a
    /// 64-bit boundary. This could be a problem on 64-bit processors.
    pub section_length: Option<u64>,
    /// The shb_hardware option is a UTF-8 string containing the description
    /// of the hardware used to create this section. The string is not
    /// zero-terminated.
    pub shb_hardware: String,
    /// The shb_os option is a UTF-8 string containing the name of the
    /// operating system used to create this section. The string is not
    /// zero-terminated.
    pub shb_os: String,
    /// The shb_userappl option is a UTF-8 string containing the name of
    /// the application used to create this section. The string is not
    /// zero-terminated.
    pub shb_userappl: String,
}

impl FromBytes for SectionHeader {
    fn parse<T: Buf>(mut buf: T, endianness: Endianness) -> Result<SectionHeader, BlockError> {
        ensure_remaining!(buf, 12);
        buf.advance(4); // the endianness - we've already parsed it
        let major_version = read_u16(&mut buf, endianness);
        let minor_version = read_u16(&mut buf, endianness);
        let section_length = match read_i64(&mut buf, endianness) {
            -1 => None,
            x => match u64::try_from(x) {
                Ok(x) => Some(x),
                Err(_) => {
                    warn!("SHB lists the length as {x}, but this is invalid");
                    None
                }
            },
        };
        let mut shb_hardware = String::new();
        let mut shb_os = String::new();
        let mut shb_userappl = String::new();
        parse_options(buf, endianness, |option_type, option_bytes| {
            match option_type {
                2 => shb_hardware = String::from_utf8_lossy(&option_bytes).to_string(),
                3 => shb_os = String::from_utf8_lossy(&option_bytes).to_string(),
                4 => shb_userappl = String::from_utf8_lossy(&option_bytes).to_string(),
                _ => (), // Ignore unknown
            }
        });
        Ok(SectionHeader {
            endianness,
            major_version,
            minor_version,
            section_length,
            shb_hardware,
            shb_os,
            shb_userappl,
        })
    }
}
