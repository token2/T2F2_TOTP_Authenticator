//! Token2 OTP USB-HID framing — **not** CTAP-HID. The OTP applet wraps APDUs in
//! its own 64-byte report frames:
//!
//! ```text
//! 21 || (flags|seq) || len || chunk[..=61] || zero-pad
//! ```
//!
//! and the host prepends a `0x00` report-ID byte, making the write 65 bytes.
//! The device may answer a long-running command with `0xC0` "still working"
//! frames the host must poll past without advancing its sequence counter.

#![allow(dead_code)] // bundled library-style modules expose a fuller API than the CLI uses

/// HID report size: 64 payload bytes. The host write is 65 bytes (leading
/// `0x00` report ID).
pub const REPORT_PAYLOAD: usize = 64;
/// Header bytes inside the 64-byte payload: magic(1) + flags/seq(1) + len(1).
pub const PAYLOAD_HEADER: usize = 3;
/// Max useful APDU bytes per frame: `64 - 3 = 61`.
pub const MAX_CHUNK: usize = REPORT_PAYLOAD - PAYLOAD_HEADER;

/// The magic byte that opens every 64-byte payload.
pub const MAGIC: u8 = 0x21;

/// Flag nibble — more chunks follow.
pub const FLAG_MORE: u8 = 0x20;
/// Flag nibble — device still working; host should poll again.
pub const FLAG_BUSY: u8 = 0xC0;
/// Flag nibble — last/only chunk.
pub const FLAG_LAST: u8 = 0x00;

/// Build the sequence of 65-byte output reports for one APDU.
pub fn build_send_frames(apdu: &[u8]) -> Vec<[u8; REPORT_PAYLOAD + 1]> {
    if apdu.is_empty() {
        let mut frame = [0u8; REPORT_PAYLOAD + 1];
        frame[1] = MAGIC;
        frame[2] = FLAG_LAST;
        frame[3] = 0;
        return vec![frame];
    }

    let mut frames = Vec::new();
    let total_chunks = apdu.len().div_ceil(MAX_CHUNK);
    for (i, chunk) in apdu.chunks(MAX_CHUNK).enumerate() {
        let is_last = i + 1 == total_chunks;
        let flags = if is_last { FLAG_LAST } else { FLAG_MORE };
        let seq = (i % 16) as u8;
        let mut frame = [0u8; REPORT_PAYLOAD + 1];
        frame[0] = 0x00; // report ID
        frame[1] = MAGIC;
        frame[2] = flags | seq;
        frame[3] = chunk.len() as u8;
        frame[4..4 + chunk.len()].copy_from_slice(chunk);
        frames.push(frame);
    }
    frames
}

/// What the caller should do after offering a received frame to the assembler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// More response frames are expected — read another report.
    NeedMore,
    /// Device is busy (a `0xC0` frame). Read another report; do not advance.
    /// `retries` counts consecutive busy frames so a "press the button" prompt
    /// can fire at ~3.
    Busy { retries: u32 },
    /// The response is complete; call `into_response`.
    Done,
}

/// Errors surfaced while assembling a HID response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    BadMagic,
    ChunkTooLong(u8),
    OutOfSequence { expected: u8, got: u8 },
    ShortFrame,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::BadMagic => write!(f, "HID frame magic byte was not 0x21"),
            FrameError::ChunkTooLong(n) => write!(f, "HID chunk length {} exceeds 61", n),
            FrameError::OutOfSequence { expected, got } => {
                write!(f, "HID frame out of sequence: expected {}, got {}", expected, got)
            }
            FrameError::ShortFrame => write!(f, "HID frame shorter than its 3-byte header"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Reassembles a multi-frame device response. The caller passes the payload
/// positioned so byte 0 is the `0x21` magic, or with the leading report-ID byte
/// still present — the magic position is detected per frame.
#[derive(Default)]
pub struct ResponseAssembler {
    buf: Vec<u8>,
    received: u8,
    busy_retries: u32,
    done: bool,
}

impl ResponseAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, raw: &[u8]) -> Result<Step, FrameError> {
        let payload: &[u8] = if raw.first() == Some(&0x00) && raw.get(1) == Some(&MAGIC) {
            &raw[1..]
        } else {
            raw
        };

        if payload.len() < PAYLOAD_HEADER {
            return Err(FrameError::ShortFrame);
        }
        if payload[0] != MAGIC {
            return Err(FrameError::BadMagic);
        }
        let flags = payload[1] & 0xF0;
        let seq = payload[1] & 0x0F;

        if flags == FLAG_BUSY {
            self.busy_retries += 1;
            return Ok(Step::Busy {
                retries: self.busy_retries,
            });
        }
        self.busy_retries = 0;

        if seq != self.received % 16 {
            return Err(FrameError::OutOfSequence {
                expected: self.received % 16,
                got: seq,
            });
        }
        self.received = self.received.wrapping_add(1);

        let len = payload[2];
        if len as usize > MAX_CHUNK {
            return Err(FrameError::ChunkTooLong(len));
        }
        let end = PAYLOAD_HEADER + len as usize;
        let chunk = payload
            .get(PAYLOAD_HEADER..end)
            .ok_or(FrameError::ShortFrame)?;
        self.buf.extend_from_slice(chunk);

        let more = (flags & FLAG_MORE) != 0;
        if more {
            Ok(Step::NeedMore)
        } else {
            self.done = true;
            Ok(Step::Done)
        }
    }

    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Consume the assembler and return `(response_data, status_word)`.
    pub fn into_response(self) -> Option<(Vec<u8>, u16)> {
        if self.buf.len() < 2 {
            return None;
        }
        let split = self.buf.len() - 2;
        let sw = ((self.buf[split] as u16) << 8) | self.buf[split + 1] as u16;
        let mut data = self.buf;
        data.truncate(split);
        Some((data, sw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_apdu_single_frame() {
        let apdu = [0x80, 0xC5, 0x01, 0x00];
        let frames = build_send_frames(&apdu);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0][1], MAGIC);
        assert_eq!(frames[0][3], 4);
        assert_eq!(&frames[0][4..8], &apdu);
    }

    #[test]
    fn sixty_two_bytes_splits() {
        let frames = build_send_frames(&vec![0xAA; 62]);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0][2], FLAG_MORE);
        assert_eq!(frames[1][2], FLAG_LAST | 1);
        assert_eq!(frames[1][3], 1);
    }

    fn payload(flags_seq: u8, chunk: &[u8]) -> Vec<u8> {
        let mut p = vec![MAGIC, flags_seq, chunk.len() as u8];
        p.extend_from_slice(chunk);
        p.resize(REPORT_PAYLOAD, 0);
        p
    }

    #[test]
    fn assemble_single_frame_with_sw() {
        let mut asm = ResponseAssembler::new();
        assert_eq!(
            asm.push(&payload(FLAG_LAST, &[b'A', b'B', 0x90, 0x00])).unwrap(),
            Step::Done
        );
        let (data, sw) = asm.into_response().unwrap();
        assert_eq!(data, b"AB");
        assert_eq!(sw, 0x9000);
    }

    #[test]
    fn busy_frames_dont_advance_sequence() {
        let mut asm = ResponseAssembler::new();
        for i in 1..=3 {
            assert_eq!(
                asm.push(&payload(FLAG_BUSY, &[])).unwrap(),
                Step::Busy { retries: i }
            );
        }
        assert_eq!(
            asm.push(&payload(FLAG_LAST, &[b'Z', 0x90, 0x00])).unwrap(),
            Step::Done
        );
        let (data, sw) = asm.into_response().unwrap();
        assert_eq!(data, b"Z");
        assert_eq!(sw, 0x9000);
    }
}
