use crate::types::*;
use byteorder::ByteOrder;

/// Defines the mapping from numeric addresses present in the packet capture and the canonical name
/// counterpart.
///
/// The Name Resolution Block (NRB) is used to support the correlation of numeric addresses
/// (present in the captured packets) and their corresponding canonical names and it is optional.
/// Having the literal names saved in the file prevents the need for performing name resolution at
/// a later time, when the association between names and addresses may be different from the one in
/// use at capture time. Moreover, the NRB avoids the need for issuing a lot of DNS requests every
/// time the trace capture is opened, and also provides name resolution when reading the capture
/// with a machine not connected to the network.
///
/// A Name Resolution Block is often placed at the beginning of the file, but no assumptions can be
/// taken about its position. Multiple NRBs can exist in a pcapng file, either due to memory
/// constraints or because additional name resolutions were performed by file processing tools,
/// like network analyzers.
///
/// A Name Resolution Block need not contain any Records, except the nrb_record_end Record which
/// MUST be the last Record. The addresses and names in NRB Records MAY be repeated multiple times;
/// i.e., the same IP address may resolve to multiple names, the same name may resolve to the
/// multiple IP addresses, and even the same address-to-name pair may appear multiple times, in the
/// same NRB or across NRBs.
///
/// This documentation is copyright (c) 2018 IETF Trust and the persons identified as the
/// authors of [this document][1]. All rights reserved. Please see the linked document for the full
/// copyright notice.
///
/// [1]: https://github.com/pcapng/pcapng
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NameResolution {
    /// Zero or more Name Resolution Records (in the TLV format), each of which contains an
    /// association between a network address and a name. An nrb_record_end MUST be added after the
    /// last Record, and MUST exist even if there are no other Records in the NRB.
    pub record_values: Vec<u8>, // TODO
}

impl<'a> FromBytes<'a> for NameResolution {
    fn parse<B: ByteOrder>(buf: &[u8]) -> Result<NameResolution> {
        Ok(NameResolution {
            record_values: Vec::from(buf),
        })
    }
}
