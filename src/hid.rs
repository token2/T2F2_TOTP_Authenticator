//! USB-HID device enumeration for Token2 FIDO keys.
//!
//! On Linux (default build) this walks `/sys/class/hidraw` to find FIDO HID
//! interfaces dependency-free. With the `hidapi-backend` feature, or on
//! macOS/Windows, it uses `hidapi`.

#![allow(dead_code)] // bundled library-style modules expose a fuller API than the CLI uses

use std::path::PathBuf;

/// A discovered HID device.
#[derive(Debug, Clone)]
pub struct HidDevice {
    pub path: PathBuf,
    pub vendor_id: u16,
    pub product_id: u16,
    pub usage_page: u16,
    pub product_name: String,
}

#[derive(Debug)]
pub struct HidError(pub String);

impl std::fmt::Display for HidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HID enumeration error: {}", self.0)
    }
}

impl std::error::Error for HidError {}

/// Enumerate connected HID devices.
pub fn enumerate() -> Result<Vec<HidDevice>, HidError> {
    backend::enumerate()
}

// --- Linux hidraw backend (default) ------------------------------------------

#[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
mod backend {
    use super::{HidDevice, HidError};
    use std::fs;
    use std::path::PathBuf;

    pub fn enumerate() -> Result<Vec<HidDevice>, HidError> {
        let mut out = Vec::new();
        let entries = match fs::read_dir("/sys/class/hidraw") {
            Ok(e) => e,
            // No hidraw class (e.g. container without it): no HID devices.
            Err(_) => return Ok(out),
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let dev_path = PathBuf::from("/dev").join(&name);
            // Resolve the device's uevent + report descriptor via sysfs.
            let sys = entry.path();
            let Some((vid, pid, product)) = read_ids(&sys) else {
                continue;
            };
            let usage_page = read_usage_page(&sys).unwrap_or(0);
            out.push(HidDevice {
                path: dev_path,
                vendor_id: vid,
                product_id: pid,
                usage_page,
                product_name: product,
            });
        }
        Ok(out)
    }

    /// Read VID/PID and product string from the parent HID device's modalias /
    /// uevent. The hidraw sysfs node has `device/uevent` with `HID_ID=` and
    /// `HID_NAME=` fields.
    fn read_ids(sys: &std::path::Path) -> Option<(u16, u16, String)> {
        let uevent = fs::read_to_string(sys.join("device/uevent")).ok()?;
        let mut vid = None;
        let mut pid = None;
        let mut name = String::new();
        for line in uevent.lines() {
            if let Some(rest) = line.strip_prefix("HID_ID=") {
                // Format: BUS:VVVVVVVV:PPPPPPPP (hex, zero-padded to 8).
                let parts: Vec<&str> = rest.split(':').collect();
                if parts.len() == 3 {
                    vid = u16::from_str_radix(&parts[1][parts[1].len().saturating_sub(4)..], 16).ok();
                    pid = u16::from_str_radix(&parts[2][parts[2].len().saturating_sub(4)..], 16).ok();
                }
            } else if let Some(rest) = line.strip_prefix("HID_NAME=") {
                name = rest.to_string();
            }
        }
        Some((vid?, pid?, name))
    }

    /// Parse the HID report descriptor to find the top-level usage page. We look
    /// for the first Usage Page (0x05) item; the FIDO page is 0xF1D0.
    fn read_usage_page(sys: &std::path::Path) -> Option<u16> {
        let desc = fs::read(sys.join("device/report_descriptor")).ok()?;
        let mut i = 0;
        while i < desc.len() {
            let b = desc[i];
            let tag = b & 0xFC;
            let size = match b & 0x03 {
                0 => 0,
                1 => 1,
                2 => 2,
                _ => 4,
            };
            // Usage Page (global item, tag 0x04).
            if tag == 0x04 {
                let mut val: u32 = 0;
                for k in 0..size {
                    if let Some(&byte) = desc.get(i + 1 + k) {
                        val |= (byte as u32) << (8 * k);
                    }
                }
                return Some(val as u16);
            }
            i += 1 + size;
        }
        None
    }
}

// --- hidapi backend (macOS/Windows, or forced on Linux) ----------------------

#[cfg(any(not(target_os = "linux"), feature = "hidapi-backend"))]
mod backend {
    use super::{HidDevice, HidError};
    use std::path::PathBuf;

    pub fn enumerate() -> Result<Vec<HidDevice>, HidError> {
        let api = hidapi::HidApi::new().map_err(|e| HidError(e.to_string()))?;
        let mut out = Vec::new();
        for info in api.device_list() {
            out.push(HidDevice {
                path: PathBuf::from(info.path().to_string_lossy().into_owned()),
                vendor_id: info.vendor_id(),
                product_id: info.product_id(),
                usage_page: info.usage_page(),
                product_name: info.product_string().unwrap_or("").to_string(),
            });
        }
        Ok(out)
    }
}
