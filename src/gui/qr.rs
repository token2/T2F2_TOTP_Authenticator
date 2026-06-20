//! Scan a TOTP QR code from the screen(s) for the Add dialog (feature `qr`).
//!
//! Captures every connected display, looks for a QR code that encodes an
//! `otpauth://totp/...` URI, and extracts the fields needed to add a profile.
//! Nothing is sent anywhere — capture and decode happen entirely locally.

/// The TOTP parameters parsed from a scanned `otpauth://` URI. Fields that the
/// URI doesn't specify are left as `None` so the caller can keep its defaults.
#[derive(Debug, Clone, Default)]
pub struct ScannedTotp {
    pub issuer: Option<String>,
    pub account: Option<String>,
    /// Base32 secret (required — its absence is an error).
    pub secret: String,
    pub algorithm: Option<Algo>,
    pub digits: Option<u8>,
    pub period: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algo {
    Sha1,
    Sha256,
    Sha512,
}

/// Capture all screens and return the first TOTP QR found, or an error
/// describing why nothing usable was scanned.
pub fn scan_screens() -> Result<ScannedTotp, String> {
    let screens = screenshots::Screen::all()
        .map_err(|e| format!("could not enumerate screens: {e}"))?;
    if screens.is_empty() {
        return Err("no screens available to scan".into());
    }

    let mut found_any_qr = false;
    let mut last_decode_note: Option<String> = None;

    for screen in screens {
        let image = match screen.capture() {
            Ok(img) => img,
            Err(_) => continue, // skip a screen we can't grab
        };
        // `screenshots` returns PNG-encoded bytes.
        let png = image.buffer();
        let dynimg = match image::load_from_memory(png) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let gray = dynimg.to_luma8();
        let mut prep = rqrr::PreparedImage::prepare(gray);
        for grid in prep.detect_grids() {
            found_any_qr = true;
            let (_meta, content) = match grid.decode() {
                Ok(c) => c,
                Err(_) => continue,
            };
            match parse_otpauth(&content) {
                Ok(t) => return Ok(t),
                Err(e) => last_decode_note = Some(e),
            }
        }
    }

    if let Some(note) = last_decode_note {
        Err(note)
    } else if found_any_qr {
        Err("a QR code was found, but it isn't a TOTP (otpauth://totp) code".into())
    } else {
        Err("no QR code found on screen — make sure the TOTP QR is visible".into())
    }
}

/// Parse an `otpauth://totp/LABEL?secret=...&issuer=...&algorithm=...` URI.
fn parse_otpauth(uri: &str) -> Result<ScannedTotp, String> {
    let uri = uri.trim();
    let rest = uri
        .strip_prefix("otpauth://totp/")
        .or_else(|| uri.strip_prefix("otpauth://TOTP/"))
        .ok_or_else(|| {
            if uri.starts_with("otpauth://hotp/") {
                "this is an HOTP code; only TOTP is supported".to_string()
            } else {
                "the QR code is not an otpauth://totp code".to_string()
            }
        })?;

    // Split label and query.
    let (label, query) = match rest.split_once('?') {
        Some((l, q)) => (l, q),
        None => (rest, ""),
    };

    let mut out = ScannedTotp::default();

    // Label is "Issuer:Account" or just "Account" (percent-encoded).
    let label = percent_decode(label);
    if let Some((issuer, account)) = label.split_once(':') {
        let issuer = issuer.trim();
        if !issuer.is_empty() {
            out.issuer = Some(issuer.to_string());
        }
        let account = account.trim();
        if !account.is_empty() {
            out.account = Some(account.to_string());
        }
    } else {
        let account = label.trim();
        if !account.is_empty() {
            out.account = Some(account.to_string());
        }
    }

    // Query parameters.
    for pair in query.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        let key = k.to_ascii_lowercase();
        let val = percent_decode(v);
        match key.as_str() {
            "secret" => out.secret = val.trim().to_string(),
            "issuer" => {
                let v = val.trim();
                if !v.is_empty() {
                    // Prefer an explicit issuer parameter over the label prefix.
                    out.issuer = Some(v.to_string());
                }
            }
            "algorithm" => {
                out.algorithm = match val.to_ascii_uppercase().as_str() {
                    "SHA1" => Some(Algo::Sha1),
                    "SHA256" => Some(Algo::Sha256),
                    "SHA512" => Some(Algo::Sha512),
                    _ => None,
                };
            }
            "digits" => out.digits = val.trim().parse().ok(),
            "period" => out.period = val.trim().parse().ok(),
            _ => {}
        }
    }

    if out.secret.is_empty() {
        return Err("the QR code has no secret — nothing to add".into());
    }
    Ok(out)
}

/// Minimal percent-decoder for otpauth labels/values (handles `%XX` and `+`).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = hex_val(bytes[i + 1]);
                let lo = hex_val(bytes[i + 2]);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push(hi << 4 | lo);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_png_pipeline() {
        // Validates the rqrr + image decode path end to end against an embedded
        // QR fixture, so the whole capture→decode→parse chain (minus the actual
        // screen grab) is exercised.
        const FIXTURE: &[u8] = include_bytes!("testdata/sample_totp_qr.png");
        let dynimg = image::load_from_memory(FIXTURE).expect("decode fixture PNG");
        let gray = dynimg.to_luma8();
        let mut prep = rqrr::PreparedImage::prepare(gray);
        let grids = prep.detect_grids();
        assert!(!grids.is_empty(), "should detect at least one QR grid");
        let (_m, content) = grids[0].decode().expect("decode QR");
        let t = parse_otpauth(&content).expect("parse otpauth");
        assert_eq!(t.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(t.algorithm, Some(Algo::Sha256));
        assert_eq!(t.digits, Some(8));
        assert_eq!(t.period, Some(60));
    }

    #[test]
    fn parses_full_uri() {
        let uri = "otpauth://totp/ACME%20Co:alice@acme.test?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60";
        let t = parse_otpauth(uri).unwrap();
        assert_eq!(t.issuer.as_deref(), Some("ACME Co"));
        assert_eq!(t.account.as_deref(), Some("alice@acme.test"));
        assert_eq!(t.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(t.algorithm, Some(Algo::Sha256));
        assert_eq!(t.digits, Some(8));
        assert_eq!(t.period, Some(60));
    }

    #[test]
    fn account_only_label() {
        let uri = "otpauth://totp/justme?secret=ABCDEFGH";
        let t = parse_otpauth(uri).unwrap();
        assert_eq!(t.account.as_deref(), Some("justme"));
        assert!(t.issuer.is_none());
        assert_eq!(t.secret, "ABCDEFGH");
        assert!(t.algorithm.is_none());
    }

    #[test]
    fn missing_secret_is_error() {
        let uri = "otpauth://totp/Acme:bob?issuer=Acme&digits=6";
        assert!(parse_otpauth(uri).is_err());
    }

    #[test]
    fn non_totp_is_error() {
        assert!(parse_otpauth("https://example.com").is_err());
        assert!(parse_otpauth("otpauth://hotp/x?secret=A&counter=1").is_err());
    }
}
