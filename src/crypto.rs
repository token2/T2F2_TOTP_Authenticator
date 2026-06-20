//! ECDH + AES-CBC payload encryption for the seed-bearing `WRITE_SEED` command.
//!
//! Flow:
//! 1. The device's `GET_ECDH_PUBKEY` reply is 64 bytes `X || Y` (no `0x04`).
//! 2. Generate a fresh ephemeral P-256 keypair per command.
//! 3. `shared = ECDH(host_priv, device_pub)`, take the 32-byte X coordinate.
//! 4. `key = SHA256(shared)` (32 bytes).
//! 5. AES-256-CBC encrypt PKCS#7-padded cleartext with a constant IV.
//!    Freshness comes from the ephemeral keypair, not the IV.
//! 6. On-wire blob = `host_pub_xy (64) || ciphertext`.
//!
//! The IV is a **constant** by design; randomizing it breaks device-side
//! decryption.

#![allow(dead_code)] // bundled library-style modules expose a fuller API than the CLI uses

use aes::Aes256;
use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey, SecretKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type Aes256CbcEnc = cbc::Encryptor<Aes256>;

/// IV used when writing or deleting OTP entries (`WRITE_SEED`).
pub const IV_OTP: [u8; 16] = [
    0x9D, 0xD8, 0x91, 0x8E, 0x34, 0xF3, 0xCC, 0xAB, 0x08, 0xCB, 0x75, 0x18, 0xF7, 0x19, 0x38, 0xF1,
];

/// Errors from the ECDH+AES seal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptError {
    /// The device pubkey was not a valid 64-byte (`X || Y`) P-256 point.
    BadDevicePubkey,
}

impl std::fmt::Display for EncryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptError::BadDevicePubkey => {
                write!(f, "device ECDH public key was not a valid P-256 point")
            }
        }
    }
}

impl std::error::Error for EncryptError {}

/// Seal `cleartext` into the on-wire `host_pub_xy || ciphertext` blob.
///
/// `device_pub_xy` is the raw 64-byte key from `GET_ECDH_PUBKEY` (no leading
/// `0x04`). A fresh ephemeral keypair is generated per call.
pub fn encrypt_seed_payload(
    device_pub_xy: &[u8],
    cleartext: &[u8],
    iv: &[u8; 16],
) -> Result<Vec<u8>, EncryptError> {
    if device_pub_xy.len() != 64 {
        return Err(EncryptError::BadDevicePubkey);
    }

    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(device_pub_xy);
    let device_point = EncodedPoint::from_bytes(sec1).map_err(|_| EncryptError::BadDevicePubkey)?;
    let device_pub = Option::<PublicKey>::from(PublicKey::from_encoded_point(&device_point))
        .ok_or(EncryptError::BadDevicePubkey)?;

    let host_secret = SecretKey::random(&mut OsRng);
    let host_pub = host_secret.public_key();

    let shared = diffie_hellman(host_secret.to_nonzero_scalar(), device_pub.as_affine());
    let session_key = Zeroizing::new({
        let mut h = Sha256::new();
        h.update(shared.raw_secret_bytes());
        h.finalize()
    });

    let mut work = Zeroizing::new(cleartext.to_vec());
    let pad_room = 16 - (cleartext.len() % 16);
    work.resize(cleartext.len() + pad_room, 0);
    let ct_len = cleartext.len();
    let ciphertext = Aes256CbcEnc::new(session_key.as_slice().into(), iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut work, ct_len)
        .expect("buffer sized for PKCS7 padding above")
        .to_vec();

    let host_point = host_pub.to_encoded_point(false);
    let host_xy = &host_point.as_bytes()[1..];

    let mut blob = Vec::with_capacity(64 + ciphertext.len());
    blob.extend_from_slice(host_xy);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_length_pubkey() {
        assert_eq!(
            encrypt_seed_payload(&[0u8; 63], b"x", &IV_OTP),
            Err(EncryptError::BadDevicePubkey)
        );
    }

    #[test]
    fn roundtrip_decrypts_on_device_side() {
        use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
        type Dec = cbc::Decryptor<aes::Aes256>;

        let device_secret = SecretKey::random(&mut OsRng);
        let device_pub = device_secret.public_key();
        let device_xy = {
            let pt = device_pub.to_encoded_point(false);
            pt.as_bytes()[1..].to_vec()
        };

        let cleartext = b"01\xC1\x00\x1E\x06\x00\x04Test\x05alice\x05Hello";
        let blob = encrypt_seed_payload(&device_xy, cleartext, &IV_OTP).unwrap();

        let host_xy = &blob[..64];
        let ciphertext = &blob[64..];
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..].copy_from_slice(host_xy);
        let host_pub = p256::PublicKey::from_sec1_bytes(&sec1).unwrap();
        let shared = diffie_hellman(device_secret.to_nonzero_scalar(), host_pub.as_affine());
        let key = {
            let mut h = Sha256::new();
            h.update(shared.raw_secret_bytes());
            h.finalize()
        };
        let mut buf = ciphertext.to_vec();
        let plain = Dec::new(key.as_slice().into(), (&IV_OTP).into())
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .unwrap();
        assert_eq!(plain, cleartext);
    }
}
