struct SectionHeader<'a> {
    /// Byte-Order Magic: magic number, whose value is the hexadecimal number 0x1A2B3C4D. This
    /// number can be used to distinguish sections that have been saved on little-endian machines
    /// from the ones saved on big-endian machines.
    byte_order_magic: u32,
    /// Major Version: number of the current mayor version of the format. Current value is 1. This
    /// value should change if the format changes in such a way that tools that can read the new
    /// format could not read the old format (i.e., the code would have to check the version number
    /// to be able to read both formats).
    major_version: u16,
    /// Minor Version: number of the current minor version of the format. Current value is 0. This
    /// value should change if the format changes in such a way that tools that can read the new
    /// format can still automatically read the new format but code that can only read the old
    /// format cannot read the new format.
    minor_version: u16,
    /// Section Length: 64-bit value specifying the length in bytes of the following section,
    /// excluding the Section Header Block itself. This field can be used to skip the section, for
    /// faster navigation inside large files. Section Length equal -1 (0xFFFFFFFFFFFFFFFF) means
    /// that the size of the section is not specified, and the only way to skip the section is to
    /// parse the blocks that it contains. Please note that if this field is valid (i.e. not -1),
    /// its value is always aligned to 32 bits, as all the blocks are aligned to 32-bit boundaries.
    /// Also, special care should be taken in accessing this field: since the alignment of all the
    /// blocks in the file is 32-bit, this field is not guaranteed to be aligned to a 64-bit
    /// boundary. This could be a problem on 64-bit workstations.
    section_length: u64,
    /// Options: optionally, a list of options (formatted according to the rules defined in Section
    /// 2.5) can be present.
    options: &'a [u8],
}

struct InterfaceDescription<'a> {
    /// LinkType: a value that defines the link layer type of this interface. The list of
    /// Standardized Link Layer Type codes is available in Appendix C.
    link_type: u16,
    /// SnapLen: maximum number of bytes dumped from each packet. The portion of each packet that
    /// exceeds this value will not be stored in the file. (TODO: Is there a need to signal "no
    /// limit"?)
    snap_len: u32,
    /// Options: optionally, a list of options (formatted according to the rules defined in Section
    /// 2.5) can be present.
    options: &'a [u8],
}

struct EnhancedPacket<'a> {
    /// Interface ID: it specifies the interface this packet comes from; the correct interface will
    /// be the one whose Interface Description Block (within the current Section of the file) is
    /// identified by the same number (see Section 3.2) of this field.
    interface_id: u32,
    /// Timestamp (High) and Timestamp (Low): high and low 32-bits of a 64-bit quantity
    /// representing the timestamp. The timestamp is a single 64-bit unsigned integer representing
    /// the number of units since 1/1/1970. The way to interpret this field is specified by the
    /// 'if_tsresol' option (see Figure 9) of the Interface Description block referenced by this
    /// packet. Please note that differently from the libpcap file format, timestamps are not saved
    /// as two 32-bit values accounting for the seconds and microseconds since 1/1/1970. They are
    /// saved as a single 64-bit quantity saved as two 32-bit words.
    timestamp_high: u32,
    timestamp_low: u32,
    /// Captured Len: number of bytes captured from the packet (i.e. the length of the Packet Data
    /// field). It will be the minimum value among the actual Packet Length and the snapshot length
    /// (defined in Figure 9). The value of this field does not include the padding bytes added at
    /// the end of the Packet Data field to align the Packet Data Field to a 32-bit boundary
    captured_len: u32,
    /// Packet Len: actual length of the packet when it was transmitted on the network. It can be
    /// different from Captured Len if the user wants only a snapshot of the packet.
    packet_len: u32,
    /// Packet Data: the data coming from the network, including link-layer headers. The actual
    /// length of this field is Captured Len. The format of the link-layer headers depends on the
    /// LinkType field specified in the Interface Description Block (see Section 3.2) and it is
    /// specified in Appendix D.
    packet_data: &'a [u8],
    /// Options: optionally, a list of options (formatted according to the rules defined in Section
    /// 2.5) can be present.
    options: &'a [u8],
}

struct SimplePacket<'a> {
    /// Packet Len: actual length of the packet when it was transmitted on the network. Can be
    /// different from captured len if the packet has been truncated by the capture process.
    packet_len: u32,
    /// Packet Data: the data coming from the network, including link-layers headers. The length of
    /// this field can be derived from the field Block Total Length, present in the Block Header,
    /// and it is the minimum value among the SnapLen (present in the Interface Description Block)
    /// and the Packet Len (present in this header).
    packet_data: &'a [u8],
}

struct ObsoletePacket<'a> {
    /// Interface ID: it specifies the interface this packet comes from; the correct interface will
    /// be the one whose Interface Description Block (within the current Section of the file) is
    /// identified by the same number (see Section 3.2) of this field.
    interface_id: u16,
    /// Drops Count: a local drop counter. It specifies the number of packets lost (by the
    /// interface and the operating system) between this packet and the preceding one. The value
    /// xFFFF (in hexadecimal) is reserved for those systems in which this information is not
    /// available.
    drops_count: u16,
    /// Timestamp (High) and Timestamp (Low): timestamp of the packet. The format of the timestamp
    /// is the same already defined in the Enhanced Packet Block (Section 3.3).
    timestamp_high: u32,
    timestamp_low: u32,
    /// Captured Len: number of bytes captured from the packet (i.e. the length of the Packet Data
    /// field). It will be the minimum value among the actual Packet Length and the snapshot length
    /// (SnapLen defined in Figure 9). The value of this field does not include the padding bytes
    /// added at the end of the Packet Data field to align the Packet Data Field to a 32-bit
    /// boundary
    captured_len: u32,
    /// Packet Len: actual length of the packet when it was transmitted on the network. Can be
    /// different from Captured Len if the user wants only a snapshot of the packet.
    packet_len: u32,
    /// Packet Data: the data coming from the network, including link-layer headers. The format of
    /// the link-layer headers depends on the LinkType field specified in the Interface Description
    /// Block (see Section 3.2) and it is specified in Appendix D. The actual length of this field
    /// is Captured Len.
    packet_data: &'a [u8],
    /// Options: optionally, a list of options (formatted according to the rules defined in Section
    /// 2.5) can be present.
    options: &'a [u8],
}

struct NameResolution<'a> {
    /// This is followed by a zero-terminated list of records (in the TLV format), each of which
    /// contains an association between a network address and a name. TODO
    record_values: &'a [u8],
}

struct InterfaceStatistics<'a> {
    /// Interface ID: it specifies the interface these statistics refers to; the correct interface
    /// will be the one whose Interface Description Block (within the current Section of the file)
    /// is identified by same number (see Section 3.2) of this field. Please note: in former
    /// versions of this document, this field was 16 bits only. As this differs from its usage in
    /// other places of this doc and as this block was not used "in the wild" before (as to the
    /// knowledge of the authors), it seems reasonable to change it to 32 bits!
    interface_id: u16,
    /// Timestamp: time this statistics refers to. The format of the timestamp is the same already
    /// defined in the Enhanced Packet Block (Section 3.3).
    timestamp_high: u32,
    timestamp_low: u32,
    /// Options: optionally, a list of options (formatted according to the rules defined in Section
    /// 2.5) can be present.
    options: &'a [u8],
}
