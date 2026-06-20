//! OTP entry types, the write/read/delete payload serializers, and the
//! variable-tail `ENUM_CODES` response parser.
//!
//! The subtlest rule: in a READ_ALL page, an entry's trailing
//! `otp_code_len || otp_code` is present **only** when the entry is TOTP *and*
//! its button-required flag is clear. Entries carry no length prefix, so a
//! parser that gets this branch wrong desynchronizes across the rest of the
//! page. READ_ONE responses always include the code.

#![allow(dead_code)] // bundled library-style modules expose a fuller API than the CLI uses

use zeroize::Zeroize;

use crate::proto::{cmd, ParseError};

/// OTP type byte: `00` = HOTP, `01` = TOTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpType {
    Hotp,
    Totp,
}

impl OtpType {
    pub fn to_byte(self) -> u8 {
        match self {
            OtpType::Hotp => 0x00,
            OtpType::Totp => 0x01,
        }
    }
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(OtpType::Hotp),
            0x01 => Some(OtpType::Totp),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            OtpType::Hotp => "HOTP",
            OtpType::Totp => "TOTP",
        }
    }
}

/// HMAC algorithm byte: `C1` = SHA1, `C2` = SHA256.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
}

impl Algorithm {
    pub fn to_byte(self) -> u8 {
        match self {
            Algorithm::Sha1 => 0xC1,
            Algorithm::Sha256 => 0xC2,
        }
    }
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0xC1 => Some(Algorithm::Sha1),
            0xC2 => Some(Algorithm::Sha256),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
        }
    }
}

/// A parsed entry as returned by `ENUM_CODES` / READ_ONE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub otp_type: OtpType,
    pub algorithm: Algorithm,
    pub timestep: u16,
    pub code_length: u8,
    pub button_required: bool,
    pub app_name: String,
    pub account_name: String,
    pub code: Option<String>,
}

/// Parameters for provisioning (or overwriting) an entry via `WRITE_SEED`. The
/// seed is the raw, Base32-decoded shared secret.
pub struct WriteEntry<'a> {
    pub otp_type: OtpType,
    pub algorithm: Algorithm,
    pub timestep: u16,
    pub code_length: u8,
    pub button_required: bool,
    pub app_name: &'a str,
    pub account_name: &'a str,
    pub seed: &'a [u8],
}

/// One page of a paginated READ_ALL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumPage {
    pub entries: Vec<Entry>,
    pub more_pages: bool,
}

fn validate_common(
    timestep: u16,
    code_length: u8,
    app_name: &str,
    account_name: &str,
    is_totp: bool,
) -> Result<(), ParseError> {
    if is_totp && timestep == 0 {
        return Err(ParseError::Invalid("timestep must be 1..=0xFFFF for TOTP"));
    }
    if !(4..=10).contains(&code_length) {
        return Err(ParseError::Invalid("code_length must be 4..=10"));
    }
    if !app_name.is_ascii() || app_name.len() > 64 {
        return Err(ParseError::Invalid("app_name must be ASCII, 0..=64 bytes"));
    }
    if !account_name.is_ascii() || account_name.is_empty() || account_name.len() > 64 {
        return Err(ParseError::Invalid("account_name must be ASCII, 1..=64 bytes"));
    }
    Ok(())
}

/// Serialize the cleartext payload for a write. This plaintext is then encrypted
/// by the ECDH+AES layer. Zeroizes on drop (carries the raw seed).
pub fn serialize_write_entry(e: &WriteEntry<'_>) -> Result<ClearText, ParseError> {
    validate_common(
        e.timestep,
        e.code_length,
        e.app_name,
        e.account_name,
        matches!(e.otp_type, OtpType::Totp),
    )?;
    if e.seed.is_empty() || e.seed.len() > 64 {
        return Err(ParseError::Invalid("seed must be 1..=64 bytes (decoded)"));
    }
    let mut buf = Vec::with_capacity(11 + e.app_name.len() + e.account_name.len() + e.seed.len());
    buf.push(e.otp_type.to_byte());
    buf.push(e.algorithm.to_byte());
    buf.extend_from_slice(&e.timestep.to_be_bytes());
    buf.push(e.code_length);
    buf.push(e.button_required as u8);
    buf.push(e.app_name.len() as u8);
    buf.extend_from_slice(e.app_name.as_bytes());
    buf.push(e.account_name.len() as u8);
    buf.extend_from_slice(e.account_name.as_bytes());
    buf.push(e.seed.len() as u8);
    buf.extend_from_slice(e.seed);
    Ok(ClearText(buf))
}

/// Serialize the cleartext for a delete: same shape as a write but with config
/// fields zeroed and an empty seed.
pub fn serialize_delete_entry(app_name: &str, account_name: &str) -> Result<ClearText, ParseError> {
    if !app_name.is_ascii() || app_name.len() > 64 {
        return Err(ParseError::Invalid("app_name must be ASCII, 0..=64 bytes"));
    }
    if !account_name.is_ascii() || account_name.is_empty() || account_name.len() > 64 {
        return Err(ParseError::Invalid("account_name must be ASCII, 1..=64 bytes"));
    }
    let mut buf = Vec::with_capacity(9 + app_name.len() + account_name.len());
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    buf.push(app_name.len() as u8);
    buf.extend_from_slice(app_name.as_bytes());
    buf.push(account_name.len() as u8);
    buf.extend_from_slice(account_name.as_bytes());
    buf.push(0x00);
    Ok(ClearText(buf))
}

/// Serialize the READ_ONE request body:
/// `01 || u64_be(ts) || u8(app_len) || app || u8(acct_len) || acct`.
pub fn serialize_read_entry(
    timestamp: u64,
    app_name: &str,
    account_name: &str,
) -> Result<Vec<u8>, ParseError> {
    if !app_name.is_ascii() || app_name.len() > 64 {
        return Err(ParseError::Invalid("app_name must be ASCII, 0..=64 bytes"));
    }
    if !account_name.is_ascii() || account_name.is_empty() || account_name.len() > 64 {
        return Err(ParseError::Invalid("account_name must be ASCII, 1..=64 bytes"));
    }
    let mut buf = Vec::with_capacity(11 + app_name.len() + account_name.len());
    buf.push(cmd::SUB_READ_ONE);
    buf.extend_from_slice(&timestamp.to_be_bytes());
    buf.push(app_name.len() as u8);
    buf.extend_from_slice(app_name.as_bytes());
    buf.push(account_name.len() as u8);
    buf.extend_from_slice(account_name.as_bytes());
    Ok(buf)
}

/// Parse a READ_ALL page: a leading partial-marker byte (high bit = more-pages,
/// low 7 bits = first entry's `type`) followed by packed length-prefix-free
/// entries.
pub fn parse_enum_page(data: &[u8]) -> Result<EnumPage, ParseError> {
    if data.is_empty() {
        return Err(ParseError::Truncated);
    }
    let more_pages = data[0] & 0x80 != 0;
    let mut stream = Vec::with_capacity(data.len());
    stream.push(data[0] & 0x7F);
    stream.extend_from_slice(&data[1..]);

    let mut cursor = Cursor::new(&stream);
    let mut entries = Vec::new();
    while !cursor.at_end() {
        entries.push(parse_one_entry(&mut cursor, false)?);
    }
    Ok(EnumPage {
        entries,
        more_pages,
    })
}

/// Parse a single READ_ONE response entry (always includes the code).
pub fn parse_read_one(data: &[u8]) -> Result<Entry, ParseError> {
    let mut cursor = Cursor::new(data);
    parse_one_entry(&mut cursor, true)
}

fn parse_one_entry(c: &mut Cursor<'_>, force_code: bool) -> Result<Entry, ParseError> {
    let type_byte = c.u8()?;
    let otp_type =
        OtpType::from_byte(type_byte).ok_or(ParseError::Malformed("unknown OTP type byte"))?;
    let algorithm =
        Algorithm::from_byte(c.u8()?).ok_or(ParseError::Malformed("unknown algorithm byte"))?;
    let timestep = c.u16_be()?;
    let code_length = c.u8()?;
    let button_required = match c.u8()? {
        0x00 => false,
        0x01 => true,
        _ => return Err(ParseError::Malformed("button flag not 0/1")),
    };
    let app_len = c.u8()? as usize;
    let app_name = c.ascii(app_len)?;
    let account_len = c.u8()? as usize;
    if account_len == 0 {
        return Err(ParseError::Malformed("account_name length is zero"));
    }
    let account_name = c.ascii(account_len)?;

    let has_code = force_code || (matches!(otp_type, OtpType::Totp) && !button_required);
    let code = if has_code {
        let code_len = c.u8()? as usize;
        Some(c.ascii(code_len)?)
    } else {
        None
    };

    Ok(Entry {
        otp_type,
        algorithm,
        timestep,
        code_length,
        button_required,
        app_name,
        account_name,
        code,
    })
}

/// A length-checked forward cursor: every accessor returns `Truncated` rather
/// than panicking, so a malformed device frame can never index out of bounds.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }
    fn at_end(&self) -> bool {
        self.pos >= self.buf.len()
    }
    fn u8(&mut self) -> Result<u8, ParseError> {
        let b = *self.buf.get(self.pos).ok_or(ParseError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }
    fn u16_be(&mut self) -> Result<u16, ParseError> {
        let hi = self.u8()? as u16;
        let lo = self.u8()? as u16;
        Ok((hi << 8) | lo)
    }
    fn ascii(&mut self, n: usize) -> Result<String, ParseError> {
        let end = self.pos.checked_add(n).ok_or(ParseError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(ParseError::Truncated)?;
        if !slice.is_ascii() {
            return Err(ParseError::Malformed("non-ASCII text field"));
        }
        self.pos = end;
        Ok(String::from_utf8_lossy(slice).into_owned())
    }
}

/// A serialized cleartext payload that scrubs itself on drop (it may carry a raw
/// OTP seed).
pub struct ClearText(Vec<u8>);

impl ClearText {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for ClearText {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_totp_page() {
        let mut payload = vec![0x01, 0xC1, 0x00, 0x1E, 0x06, 0x00, 0x04];
        payload.extend_from_slice(b"Test");
        payload.push(0x05);
        payload.extend_from_slice(b"alice");
        payload.push(0x06);
        payload.extend_from_slice(b"123456");

        let page = parse_enum_page(&payload).unwrap();
        assert!(!page.more_pages);
        assert_eq!(page.entries.len(), 1);
        let e = &page.entries[0];
        assert_eq!(e.otp_type, OtpType::Totp);
        assert_eq!(e.app_name, "Test");
        assert_eq!(e.account_name, "alice");
        assert_eq!(e.code.as_deref(), Some("123456"));
    }

    #[test]
    fn hotp_entry_has_no_code_tail() {
        let mut payload = vec![0x00, 0xC1, 0x00, 0x00, 0x00, 0x00, 0x01];
        payload.extend_from_slice(b"a");
        payload.push(0x01);
        payload.extend_from_slice(b"x");
        payload.extend_from_slice(&[0x01, 0xC1, 0x00, 0x1E, 0x06, 0x00, 0x01]);
        payload.extend_from_slice(b"b");
        payload.push(0x01);
        payload.extend_from_slice(b"y");
        payload.push(0x06);
        payload.extend_from_slice(b"999999");

        let page = parse_enum_page(&payload).unwrap();
        assert_eq!(page.entries.len(), 2);
        assert_eq!(page.entries[0].otp_type, OtpType::Hotp);
        assert_eq!(page.entries[0].code, None);
        assert_eq!(page.entries[1].code.as_deref(), Some("999999"));
    }

    #[test]
    fn button_required_totp_has_no_code_tail() {
        let mut payload = vec![0x01, 0xC1, 0x00, 0x1E, 0x06, 0x01, 0x01];
        payload.extend_from_slice(b"b");
        payload.push(0x01);
        payload.extend_from_slice(b"y");
        let page = parse_enum_page(&payload).unwrap();
        assert!(page.entries[0].button_required);
        assert_eq!(page.entries[0].code, None);
    }

    #[test]
    fn write_entry_cleartext() {
        let we = WriteEntry {
            otp_type: OtpType::Totp,
            algorithm: Algorithm::Sha1,
            timestep: 30,
            code_length: 6,
            button_required: false,
            app_name: "Test",
            account_name: "alice",
            seed: b"Hello",
        };
        let ct = serialize_write_entry(&we).unwrap();
        let mut want = vec![0x01, 0xC1, 0x00, 0x1E, 0x06, 0x00, 0x04];
        want.extend_from_slice(b"Test");
        want.push(0x05);
        want.extend_from_slice(b"alice");
        want.push(0x05);
        want.extend_from_slice(b"Hello");
        assert_eq!(ct.as_bytes(), want.as_slice());
    }

    #[test]
    fn truncated_record_is_error_not_panic() {
        let payload = vec![0x01, 0xC1, 0x00, 0x1E, 0x06, 0x00, 0x04, b'T', b'e'];
        assert_eq!(parse_enum_page(&payload), Err(ParseError::Truncated));
    }
}
