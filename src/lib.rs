//! T2 TOTP Authenticator — device-access library shared by the `t2totp` CLI and
//! the `t2totp-gui` desktop app.
//!
//! Manages the TOTP profiles on a Token2 second-generation FIDO2 key over
//! USB-HID or NFC/PC-SC, identifying NFC-attached keys by reading their serial
//! number. See [`transport::OtpSession`] for the high-level entry point.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod entry;
pub mod hid;
pub mod hidframe;
pub mod proto;
pub mod transport;

/// The Auto-OTP marker the reference Windows app appends to an issuer to flag
/// the profile its global hotkey emits. Plain text in the issuer field, so it
/// round-trips between tools.
pub const AUTO_TAG: &str = "[A]";
