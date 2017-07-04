struct Block<'a, R: 'a + BufRead> {
    btype: BlockType,
    length: usize,
    body: &'a [u8],
    rdr: &'a mut R,
}

pub struct BlockReader<R> {
    rdr: BufReader<R>,
    endianness: Endianness,
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

impl<R: Read> BlockReader<R> {
    pub fn new(rdr: R) -> BlockReader<R> {
        BlockReader {
            rdr: BufReader::with_capacity(10_000_000, rdr),
            endianness: Endianness::Big, // arbitrary
        }
    }

    fn next_block(&mut self) -> Result<Option<Block<BufReader<R>>>> {
        self.peek_for_shb()?;
        match self.endianness {
            Endianness::Big => Block::from_rdr::<BigEndian>(&mut self.rdr),
            Endianness::Little => Block::from_rdr::<LittleEndian>(&mut self.rdr),
        }
    }

    /// First we just need to check if it's an SHB, and set the endinanness if it is. This function
    /// doesn't consume anything from the buffer, it just peeks. If this function fails due to not
    /// having enough bytes in the buffer, let's just carry on - if it's an SHB `read_block` will
    /// fail too.
    fn peek_for_shb(&mut self) -> Result<()> {
        let buf = self.rdr.fill_buf().unwrap();
        if buf.len() < 4 { return Ok(()); }
        let block_type = &buf[..4];
        if block_type == &[0x0A, 0x0D, 0x0D, 0x0A] {
            if buf.len() < 12 { return Ok(()); }
            let mut magic = [0;4]; magic.copy_from_slice(&buf[8..12]);
            if magic == [0x1A, 0x2B, 0x3C, 0x4D] {
                self.endianness = Endianness::Big;
            } else if magic == [0x4D, 0x3C, 0x2B, 0x1A] {
                self.endianness = Endianness::Little;
            } else {
                return Err(Error::DidntUnderstandMagicNumber(magic));
            }
            debug!("SHB coming up, setting endianness to {:?}", self.endianness);
        }
        Ok(())
    }
}

impl<'a, R: BufRead> Block<'a, R> {
    fn from_rdr<B: ByteOrder>(rdr: &'a mut R) -> Result<Option<Block<'a, R>>> {
        let buf = rdr.fill_buf().unwrap();
        if buf.len() < 8 { return Ok(None); }
        let block_type   = B::read_u32(&buf[..4]);
        let block_length = B::read_u32(&buf[4..8]) as usize;
        if buf.len() < 12 + block_length { return Ok(None) }
        debug!("Got block, type {:x}, len {}", block_type, block_length);
        let body = &buf[8..block_length - 4];
        let block_length_2 = B::read_u32(&buf[block_length - 4..block_length]) as usize;
        assert_eq!(block_length, block_length_2, "Block's start and end lengths don't match");
        Ok(Some(Block {
            btype: match_block_type(block_type)?,
            length: block_length,
            body: body,
            rdr: rdr,
        }))
    }
}

impl<'a, R: BufRead> Drop for Block<'a, R> {
    fn drop(&mut self) {
        self.rdr.consume(self.length);
    }
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
