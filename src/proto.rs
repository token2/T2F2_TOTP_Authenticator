//! Pure-byte protocol layer for the Token2 second-generation FIDO2 key's
//! on-device OTP management applet — building APDUs, parsing responses, and the
//! base32/serial helpers. Hardware-free: no I/O lives here.
//!
//! This is the *OTP management* applet (provisioning and reading the TOTP/HOTP
//! entries the key stores), **not** CTAP/FIDO2 — that is the standard FIDO
//! interface and is untouched by this tool.

#![allow(dead_code)] // bundled library-style modules expose a fuller API than the CLI uses

use zeroize::Zeroizing;

// --- USB / applet identity ----------------------------------------------------

/// USB Vendor ID for Token2 FIDO2 keys (decimal 13470).
pub const USB_VID: u16 = 0x349E;
/// A USB Product ID seen on these keys (they ship under several; matched only as
/// a fallback alongside the FIDO usage page and product string).
pub const USB_PID: u16 = 0x0022;
/// Product string to match alongside the VID when the PID is ambiguous.
pub const USB_PRODUCT: &str = "FIDO2 Security Key";
/// HID usage page these keys expose (the standard FIDO/U2F page).
pub const FIDO_USAGE_PAGE: u16 = 0xF1D0;

/// SELECT AID for the OTP management applet.
pub const OTP_APPLET_AID: [u8; 8] = [0xF0, 0x00, 0x00, 0x01, 0x4F, 0x74, 0x70, 0x01];
/// SELECT AID for the FIDO applet — needed before reading the serial over PC/SC.
pub const FIDO_APPLET_AID: [u8; 8] = [0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];

/// APDU command headers (`CLA INS P1 P2`).
pub mod cmd {
    /// `GET_ECDH_PUBKEY` — device returns its raw 64-byte P-256 pubkey.
    pub const GET_ECDH_PUBKEY: [u8; 4] = [0x80, 0xC5, 0x01, 0x00];
    /// `READ_CONFIG` — device returns the device-info block.
    pub const READ_CONFIG: [u8; 4] = [0x80, 0xC5, 0x02, 0x00];
    /// `ENABLE_TOTP` — 1 byte (00/01).
    pub const ENABLE_TOTP: [u8; 4] = [0x80, 0xC5, 0x02, 0x05];
    /// `ENUM_CODES` — host sends subcommand + args.
    pub const ENUM_CODES: [u8; 4] = [0x80, 0xC5, 0x05, 0x00];
    /// `ENUM_CODES_CONTINUE` — host sends an 8-byte timestamp.
    pub const ENUM_CODES_CONTINUE: [u8; 4] = [0x80, 0xC5, 0x05, 0x01];
    /// `WRITE_SEED` — encrypted entry write, or empty body for erase-all.
    pub const WRITE_SEED: [u8; 4] = [0x80, 0xC5, 0x05, 0x02];
    /// `GET_INFO` on the FIDO applet — read serial number.
    pub const READ_SERIAL_INS: [u8; 4] = [0x80, 0x33, 0x00, 0x00];

    /// ENUM_CODES subcommand: read one entry by name.
    pub const SUB_READ_ONE: u8 = 0x01;
    /// ENUM_CODES subcommand: paginated read-all.
    pub const SUB_READ_ALL: u8 = 0x03;
}

/// ISO-7816 status words this applet returns.
pub mod sw {
    pub const OK: u16 = 0x9000;
    pub const ENTRY_NOT_FOUND: u16 = 0x6A80;
    pub const ENTRY_NOT_FOUND_ALT: u16 = 0x6A83;
    pub const NOT_ENOUGH_SPACE: u16 = 0x6A84;
    pub const HID_NOT_SUPPORTED: u16 = 0x6A86;
    pub const BUTTON_TIMEOUT: u16 = 0x6FF9;
}

/// An expected, surfaced-to-user applet error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OtpError {
    /// `6A80` / `6A83`. On a clean READ_ALL this means "zero entries".
    EntryNotFound,
    /// `6A84` — device storage is full.
    NotEnoughSpace,
    /// `6FF9` — timed out waiting for a confirming button press.
    ButtonPressRequired,
    /// `6A86` — this model does not expose HOTP-over-HID.
    HidNotSupported,
    /// Any other non-`9000` status word.
    BadStatusCode(u16),
}

impl OtpError {
    /// Map a status word to an error, or `Ok(())` for `9000`.
    pub fn check(sw: u16) -> Result<(), OtpError> {
        match sw {
            sw::OK => Ok(()),
            sw::ENTRY_NOT_FOUND | sw::ENTRY_NOT_FOUND_ALT => Err(OtpError::EntryNotFound),
            sw::NOT_ENOUGH_SPACE => Err(OtpError::NotEnoughSpace),
            sw::BUTTON_TIMEOUT => Err(OtpError::ButtonPressRequired),
            sw::HID_NOT_SUPPORTED => Err(OtpError::HidNotSupported),
            other => Err(OtpError::BadStatusCode(other)),
        }
    }

    /// True for the `EntryNotFound` a READ_ALL returns on an empty token.
    pub fn is_empty_token(&self) -> bool {
        matches!(self, OtpError::EntryNotFound)
    }
}

impl std::fmt::Display for OtpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OtpError::EntryNotFound => write!(f, "entry not found"),
            OtpError::NotEnoughSpace => write!(f, "not enough space on device"),
            OtpError::ButtonPressRequired => {
                write!(f, "timed out waiting for a button press on the key")
            }
            OtpError::HidNotSupported => write!(f, "HOTP-over-HID is not supported on this model"),
            OtpError::BadStatusCode(sw) => write!(f, "unexpected status word {:#06X}", sw),
        }
    }
}

impl std::error::Error for OtpError {}

// --- APDU builders ------------------------------------------------------------

/// Build an extended-length APDU: `CLA INS P1 P2 00 Lc_hi Lc_lo data...`.
/// An empty body sends just the 4-byte header (the device reads a bodyless
/// WRITE_SEED as erase-all).
pub fn build_apdu(header: [u8; 4], data: &[u8]) -> Vec<u8> {
    let len = data.len();
    assert!(len <= 0xFFFF, "extended APDU body exceeds 16-bit Lc");
    let mut out = Vec::with_capacity(7 + len);
    out.extend_from_slice(&header);
    if len > 0 {
        out.push(0x00);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
        out.extend_from_slice(data);
    }
    out
}

/// Build the short-form SELECT-by-name APDU: `00 A4 04 00 Lc aid...`.
pub fn build_select(aid: &[u8]) -> Vec<u8> {
    assert!(!aid.is_empty() && aid.len() <= 255, "SELECT AID length");
    let mut out = Vec::with_capacity(5 + aid.len());
    out.extend_from_slice(&[0x00, 0xA4, 0x04, 0x00]);
    out.push(aid.len() as u8);
    out.extend_from_slice(aid);
    out
}

/// Build the `GET_ECDH_PUBKEY` request: short case-2 `80 C5 01 00 00`.
pub fn get_ecdh_pubkey() -> Vec<u8> {
    let mut v = cmd::GET_ECDH_PUBKEY.to_vec();
    v.push(0x00); // Le = return all available
    v
}

/// Build the `READ_CONFIG` request for `num_bytes` (clamped to 1..=64).
pub fn read_config(num_bytes: u8) -> Vec<u8> {
    let n = num_bytes.clamp(1, 64);
    let mut v = cmd::READ_CONFIG.to_vec();
    v.push(n); // P3 = Le
    v
}

/// Build the `ENABLE_TOTP` APDU.
pub fn enable_totp(enabled: bool) -> Vec<u8> {
    build_apdu(cmd::ENABLE_TOTP, &[enabled as u8])
}

/// Build the bodyless `WRITE_SEED` that erases every entry.
pub fn erase_all() -> Vec<u8> {
    build_apdu(cmd::WRITE_SEED, &[])
}

/// Build the FIDO-applet serial-number request: `D1 10` + 16 zero bytes.
pub fn read_serial_request() -> Vec<u8> {
    let mut payload = [0u8; 18];
    payload[0] = 0xD1;
    payload[1] = 0x10;
    build_apdu(cmd::READ_SERIAL_INS, &payload)
}

/// Serialize the READ_ALL request body: `03 || u64_be(ts)`.
pub fn serialize_enum_all(timestamp: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(9);
    buf.push(cmd::SUB_READ_ALL);
    buf.extend_from_slice(&timestamp.to_be_bytes());
    buf
}

// --- serial parsing -----------------------------------------------------------

/// Parse the serial-number response: `D1 len ascii_hex...`. The serial is
/// double-encoded — ASCII-hex characters the host then hex-decodes to bytes.
pub fn parse_serial(data: &[u8]) -> Result<Vec<u8>, ParseError> {
    if data.len() < 2 || data[0] != 0xD1 {
        return Err(ParseError::Truncated);
    }
    let sn_len = data[1] as usize;
    let hex = data.get(2..2 + sn_len).ok_or(ParseError::Truncated)?;
    decode_ascii_hex(hex)
}

fn decode_ascii_hex(hex: &[u8]) -> Result<Vec<u8>, ParseError> {
    if hex.len() % 2 != 0 {
        return Err(ParseError::Malformed("serial hex length is odd"));
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for pair in hex.chunks_exact(2) {
        let hi = hex_nibble(pair[0]).ok_or(ParseError::Malformed("non-hex char in serial"))?;
        let lo = hex_nibble(pair[1]).ok_or(ParseError::Malformed("non-hex char in serial"))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Render bytes as lower-case hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// --- device-info --------------------------------------------------------------

/// Decoded `READ_CONFIG` device-info block. Each meaningful bit is a named
/// boolean. "bit 1" is `value & 0x01`, "bit 8" is `value & 0x80`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub transfer_type: u8,
    pub device_config: u8,
    pub appearance: [u8; 4],
    pub fido_version: [u8; 3],
    pub device_extension: u8,
    pub raw_len: usize,
}

impl DeviceInfo {
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.is_empty() {
            return Err(ParseError::Truncated);
        }
        let get = |i: usize| data.get(i).copied().unwrap_or(0);
        Ok(DeviceInfo {
            transfer_type: data[0],
            device_config: get(1),
            appearance: [get(2), get(3), get(4), get(5)],
            fido_version: [get(6), get(7), get(8)],
            device_extension: get(9),
            raw_len: data.len(),
        })
    }

    /// Whether the response actually carried the config byte (byte 1), vs. a
    /// short CCID/NFC stub that only carried byte 0.
    pub fn has_config_byte(&self) -> bool {
        self.raw_len >= 2
    }

    // transfer-type bits (byte 0)
    pub fn fido_disabled(&self) -> bool {
        self.transfer_type & 0x01 != 0
    }
    pub fn hotp_keystroke_disabled(&self) -> bool {
        self.transfer_type & 0x02 != 0
    }
    pub fn ccid_disabled(&self) -> bool {
        self.transfer_type & 0x04 != 0
    }

    // device-config bits (byte 1)
    pub fn fido_pin_set(&self) -> bool {
        self.device_config & 0x02 != 0
    }
    pub fn hotp_supported(&self) -> bool {
        self.device_config & 0x04 != 0
    }
    pub fn fingerprint_present(&self) -> bool {
        self.device_config & 0x08 != 0
    }
    pub fn nfc_supported(&self) -> bool {
        self.device_config & 0x10 != 0
    }
    pub fn pin_locked(&self) -> bool {
        self.device_config & 0x40 != 0
    }

    // device-extension bits (byte 9)
    pub fn totp_supported(&self) -> bool {
        self.device_extension & 0x01 != 0
    }
    pub fn fido_21_supported(&self) -> bool {
        self.device_extension & 0x02 != 0
    }
    pub fn ccid_supported(&self) -> bool {
        self.device_extension & 0x10 != 0
    }
}

// --- base32 -------------------------------------------------------------------

/// Validate a decoded seed length: 1..=64 bytes.
pub fn validate_seed_len(decoded_len: usize) -> Result<(), &'static str> {
    match decoded_len {
        1..=64 => Ok(()),
        0 => Err("seed is empty after Base32 decode"),
        _ => Err("seed exceeds 64 bytes after Base32 decode"),
    }
}

/// Decode a user-supplied Base32 (RFC 4648) seed, re-padding stripped `=` and
/// ignoring whitespace/case. Returns bytes that zeroize on drop.
pub fn decode_base32_seed(s: &str) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let upper = cleaned.trim_end_matches('=').to_ascii_uppercase();
    let decoded = base32_decode(&upper)?;
    validate_seed_len(decoded.len())?;
    Ok(Zeroizing::new(decoded))
}

fn base32_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    for ch in s.bytes() {
        let val = ALPHABET
            .iter()
            .position(|&a| a == ch)
            .ok_or("invalid Base32 character in seed")? as u64;
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Ok(out)
}

// --- shared parse error -------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Ran off the end of the buffer mid-record.
    Truncated,
    /// A field held a value outside its documented range.
    Malformed(&'static str),
    /// A validation rule failed before sending.
    Invalid(&'static str),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Truncated => write!(f, "response truncated mid-record"),
            ParseError::Malformed(s) => write!(f, "malformed response: {}", s),
            ParseError::Invalid(s) => write!(f, "invalid parameter: {}", s),
        }
    }
}

impl std::error::Error for ParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_config_apdu_form() {
        assert_eq!(read_config(64), vec![0x80, 0xC5, 0x02, 0x00, 0x40]);
        assert_eq!(*read_config(0).last().unwrap(), 0x01);
        assert_eq!(*read_config(200).last().unwrap(), 0x40);
        assert_eq!(get_ecdh_pubkey(), vec![0x80, 0xC5, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn extended_apdu_layout() {
        let mut data = vec![cmd::SUB_READ_ALL];
        data.extend_from_slice(&0u64.to_be_bytes());
        let apdu = build_apdu(cmd::ENUM_CODES, &data);
        assert_eq!(
            apdu,
            vec![0x80, 0xC5, 0x05, 0x00, 0x00, 0x00, 0x09, 0x03, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn erase_all_is_bodyless_write_seed() {
        assert_eq!(erase_all(), vec![0x80, 0xC5, 0x05, 0x02]);
    }

    #[test]
    fn select_uses_short_lc() {
        assert_eq!(
            build_select(&OTP_APPLET_AID),
            vec![0x00, 0xA4, 0x04, 0x00, 0x08, 0xF0, 0x00, 0x00, 0x01, 0x4F, 0x74, 0x70, 0x01]
        );
    }

    #[test]
    fn status_word_mapping() {
        assert_eq!(OtpError::check(0x9000), Ok(()));
        assert_eq!(OtpError::check(0x6A80), Err(OtpError::EntryNotFound));
        assert_eq!(OtpError::check(0x6A84), Err(OtpError::NotEnoughSpace));
        assert!(OtpError::check(0x6A80).unwrap_err().is_empty_token());
    }

    #[test]
    fn serial_double_decode() {
        let resp = [
            0xD1, 0x0A, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0',
        ];
        assert_eq!(parse_serial(&resp).unwrap(), vec![0x12, 0x34, 0x56, 0x78, 0x90]);
    }

    #[test]
    fn base32_seed_decodes_hello() {
        assert_eq!(&decode_base32_seed("JBSWY3DP").unwrap()[..], b"Hello");
        assert_eq!(&decode_base32_seed("jbswy3dp").unwrap()[..], b"Hello");
    }

    #[test]
    fn device_info_short_response() {
        let info = DeviceInfo::parse(&[0x02]).unwrap();
        assert!(!info.fido_disabled());
        assert!(info.hotp_keystroke_disabled());
        assert!(!info.has_config_byte());
        assert!(DeviceInfo::parse(&[]).is_err());
    }
}
