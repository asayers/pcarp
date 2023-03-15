use crate::block::*;
use bytes::Buf;
use thiserror::Error;

/// Look for a complete frame at the front of the given buffer
///
/// If the buffer contains a complete frame, this function returns the block
/// type and data length.  If the buffer is empty or contains an incomplete
/// frame, it returns `None`.  If the buffer contains an invalid frame,
/// it returns an error.  Such errors should be treated as fatal.
pub(crate) fn parse_frame(
    buf: &[u8],
    endianness: &mut Endianness,
) -> Result<Option<(BlockType, usize)>, FrameError> {
    // Even a block with an empty body would be 12 bytes long:
    //
    //     type (4) + len (4) + body (0) + len (4) = 12
    //
    // So this check doesn't rule out any blocks.
    //
    // Furthermore, this is enough to cover the first two get_u32()s, and
    // also the magic bytes in the case of an SHB.
    if buf.len() < 12 {
        return Ok(None);
    }

    let read_u32 = |i: usize, endianness: Endianness| -> u32 {
        match endianness {
            Endianness::Big => (&buf[i..i + 4]).get_u32(),
            Endianness::Little => (&buf[i..i + 4]).get_u32_le(),
        }
    };

    let block_type = read_u32(0, *endianness);
    if block_type == 0x0A0D_0D0A {
        // We have a new section coming up.  We may need to change the
        // endianness.
        *endianness = match &buf[8..12] {
            &[0x1A, 0x2B, 0x3C, 0x4D] => Endianness::Big,
            &[0x4D, 0x3C, 0x2B, 0x1A] => Endianness::Little,
            x => return Err(FrameError::DidntUnderstandMagicBytes(x.try_into().unwrap())),
        };
        trace!("Found SHB; setting endianness to {:?}", *endianness);
    }
    let block_type = BlockType::from(block_type);

    let block_len = read_u32(4, *endianness) as usize;
    if block_len < 12 {
        return Err(FrameError::BlockLengthTooSmall(block_len));
    }
    if buf.len() < block_len {
        return Ok(None);
    }

    let block_len_2 = read_u32(block_len - 4, *endianness) as usize;
    if block_len != block_len_2 {
        return Err(FrameError::BlockLengthMismatch(block_len, block_len_2));
    }

    let data_len = block_len - 12;
    Ok(Some((block_type, data_len)))
}

/// The pcap's superstructure is corrupt; further parsing is impossible
#[derive(Debug, Error)]
pub enum FrameError {
    #[error("Didn't understand magic bytes {0:?}")]
    DidntUnderstandMagicBytes([u8; 4]),
    #[error("Block's start length was {0} but its end length was {1}")]
    BlockLengthMismatch(usize, usize),
    #[error("Block's length is {0} bytes, but the minimum length is 12")]
    BlockLengthTooSmall(usize),
}
