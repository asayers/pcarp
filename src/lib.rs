pub struct BlockReader<R, F> {
    rdr: BufReader<R>,
    endianness: Endianness,
    handle_packet: F,
}

pub enum Error {
    DidntUnderstandMagicNumber([u8;4]),
    UnknownBlockType(u32),
    NotEnoughBytes,
}

impl<R: Read, F: Fn(&[u8])> BlockReader<R, F> {
    pub fn new(rdr: R, handle_packet: F) -> BlockReader<R, F> {
        BlockReader {
            rdr: BufReader::with_capacity(10_000_000, rdr),
            endianness: Endianness::Big, // arbitrary
            handle_packet: F,
        }
    }

    fn next_block(&mut self) -> Result<Option<Block<BufReader<R>>>> {
        if let Some(new_endianness) = peek_for_shb(&mut self.rdr)? {
            debug!("SHB coming up, setting endianness to {:?}", new_endianness);
            self.endianness = new_endianness;
        }
        match self.endianness {
            Endianness::Big    => read_block::<BigEndian>(&mut self.rdr),
            Endianness::Little => read_block::<LittleEndian>(&mut self.rdr),
        }
    }

    fn read_block<B: ByteOrder>(&mut self) -> Result<()> {
        let buf = self.rdr.fill_buf().unwrap();
        if buf.len() < 8 { return Err(NotEnoughBytes); }
        let block_type   = B::read_u32(&buf[..4]);
        let block_length = B::read_u32(&buf[4..8]) as usize;
        if buf.len() < 12 + block_length { return Err(NotEnoughBytes); }
        debug!("Got block, type {:x}, len {}", block_type, block_length);
        let body = &buf[8..block_length - 4];
        let block_length_2 = B::read_u32(&buf[block_length - 4..block_length]) as usize;
        assert_eq!(block_length, block_length_2, "Block's start and end lengths don't match");
        self.handle_block::<B>(self, block_type, body)?;
        self.rdr.consume(block_length);
    }

    fn read_block<B: ByteOrder>(&mut self, block_type: u32, body: &[u8]) -> Result<()> {
        match match_block_type(block_type)? {
            InterfaceDescription, // mandatory
            Packet,               // obsolete
            SimplePacket,
            NameResolution,
            InterfaceStatistics,
            EnhancedPacket,
            IRIGTimestamp,        // ignored
            Arinc429,             // ignored
            SectionHeader,        // mandatory
        }
    }
}

/// First we just need to check if it's an SHB, and set the endinanness if it is. This function
/// doesn't consume anything from the buffer, it just peeks.
fn peek_for_shb<R: BufRead>(rdr: &mut R) -> Result<Option<Endianness>> {
    let buf = rdr.fill_buf().unwrap();
    if buf.len() < 4 { return Err(Error::NotEnoughBytes); }
    let block_type = &buf[..4];
    if block_type == &[0x0A, 0x0D, 0x0D, 0x0A] {
        if buf.len() < 12 { return Err(Error::NotEnoughBytes); }
        let mut magic = [0;4]; magic.copy_from_slice(&buf[8..12]);
        if magic == [0x1A, 0x2B, 0x3C, 0x4D] {
            Ok(Some(Endianness::Big));
        } else if magic == [0x4D, 0x3C, 0x2B, 0x1A] {
            Ok(Some(Endianness::Little));
        } else {
            Err(Error::DidntUnderstandMagicNumber(magic));
        }
    } else {
        Ok(None)
    }
}





#[derive(Clone, PartialEq, Debug)]
pub enum BlockType {
    InterfaceDescription, // mandatory
    Packet,               // obsolete
    SimplePacket,
    NameResolution,
    InterfaceStatistics,
    EnhancedPacket,
    IRIGTimestamp,        // ignored
    Arinc429,             // ignored
    SectionHeader,        // mandatory
}

fn match_block_type(block_type: u32) -> Result<BlockType> {
    match block_type {
        0x00000001 => Ok(BlockType::InterfaceDescription),
        0x00000002 => Ok(BlockType::Packet),
        0x00000003 => Ok(BlockType::SimplePacket),
        0x00000004 => Ok(BlockType::NameResolution),
        0x00000005 => Ok(BlockType::InterfaceStatistics),
        0x00000006 => Ok(BlockType::EnhancedPacket),
        0x00000007 => Ok(BlockType::IRIGTimestamp),
        0x00000008 => Ok(BlockType::Arinc429),
        0x0A0D0D0A => Ok(BlockType::SectionHeader),
        n => Err(Error::UnknownBlockType(n)),
    }
}
