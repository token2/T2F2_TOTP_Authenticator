//! Global Auto-OTP hotkey: a system-wide key combo that reads the live code of
//! the `[A]`-tagged profile and types it into whatever window has focus — the
//! desktop counterpart to Token2's Windows Auto-OTP hotkey.
//!
//! Feature-gated behind `hotkey` (heavy, platform-specific deps). The actual
//! device read + keystroke injection run on a worker thread so a slow key or a
//! touch wait never blocks the UI.
//!
//! Platform notes:
//! * Windows / macOS / X11: fully supported.
//! * Wayland: global hotkeys are restricted by the compositor; registration may
//!   fail or require a portal. The error is surfaced rather than swallowed.

use std::sync::mpsc::Receiver;
use std::sync::mpsc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use global_hotkey::{
    hotkey::{Code, HotKey, Modifiers},
    GlobalHotKeyEvent, GlobalHotKeyManager, HotKeyState,
};

use t2totp::transport::{Interface, OtpSession};
use t2totp::AUTO_TAG;

/// A configurable hotkey binding: a set of modifiers plus a main key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HotkeyBinding {
    pub ctrl: bool,
    pub shift: bool,
    pub alt: bool,
    /// Super/Windows/Command key.
    pub meta: bool,
    pub key: Code,
}

impl Default for HotkeyBinding {
    fn default() -> Self {
        // The supported family is Left Ctrl + Left Alt + a letter (matching the
        // Token2 device-side Auto-OTP convention). The letter set is restricted
        // to ones that don't collide with common system/app shortcuts.
        HotkeyBinding {
            ctrl: true,
            shift: false,
            alt: true,
            meta: false,
            key: Code::KeyA,
        }
    }
}

impl HotkeyBinding {
    fn modifiers(&self) -> Modifiers {
        let mut m = Modifiers::empty();
        if self.ctrl {
            m |= Modifiers::CONTROL;
        }
        if self.shift {
            m |= Modifiers::SHIFT;
        }
        if self.alt {
            m |= Modifiers::ALT;
        }
        if self.meta {
            m |= Modifiers::META;
        }
        m
    }

    fn to_hotkey(self) -> HotKey {
        HotKey::new(Some(self.modifiers()), self.key)
    }

    /// True if at least one modifier is held — global hotkeys without a modifier
    /// are a bad idea (they'd swallow the bare key everywhere).
    pub fn has_modifier(&self) -> bool {
        self.ctrl || self.shift || self.alt || self.meta
    }

    /// Human-readable label, e.g. "Ctrl + Alt + T".
    pub fn label(&self) -> String {
        let mut parts: Vec<&str> = Vec::new();
        if self.ctrl {
            parts.push("Ctrl");
        }
        if self.shift {
            parts.push("Shift");
        }
        if self.alt {
            parts.push("Alt");
        }
        if self.meta {
            parts.push(SUPER_LABEL);
        }
        let key = key_label(self.key);
        parts.push(&key);
        parts.join(" + ")
    }
}

/// Platform-appropriate name for the Super/Meta modifier.
#[cfg(target_os = "macos")]
const SUPER_LABEL: &str = "Cmd";
#[cfg(target_os = "windows")]
const SUPER_LABEL: &str = "Win";
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
const SUPER_LABEL: &str = "Super";

/// The keys offered in the settings picker, with display labels.
/// The keys offered in the settings picker, with display labels. The hotkey is
/// always Ctrl+Alt + one of these letters — the exact set the Token2 device
/// supports for Auto-OTP, chosen to avoid clashing with common shortcuts.
/// (Device index → letter: 0=A,1=B,2=C,3=F,4=N,5=Q,6=S,7=V,8=X,9=Z.)
pub fn selectable_keys() -> &'static [(Code, &'static str)] {
    &[
        (Code::KeyA, "A"),
        (Code::KeyB, "B"),
        (Code::KeyC, "C"),
        (Code::KeyF, "F"),
        (Code::KeyN, "N"),
        (Code::KeyQ, "Q"),
        (Code::KeyS, "S"),
        (Code::KeyV, "V"),
        (Code::KeyX, "X"),
        (Code::KeyZ, "Z"),
    ]
}

fn key_label(code: Code) -> String {
    selectable_keys()
        .iter()
        .find(|(c, _)| *c == code)
        .map(|(_, l)| (*l).to_string())
        .unwrap_or_else(|| format!("{code:?}"))
}

/// A stable, persistable name for a key code (its `Debug` form, e.g. "KeyT").
pub fn key_name(code: Code) -> String {
    format!("{code:?}")
}

/// Parse a key name produced by [`key_name`] back to a `Code`; falls back to the
/// default key when unrecognised.
pub fn key_from_name(name: &str) -> Code {
    selectable_keys()
        .iter()
        .map(|(c, _)| *c)
        .find(|c| format!("{c:?}") == name)
        .unwrap_or(HotkeyBinding::default().key)
}

/// Outcome of a hotkey-driven type attempt, for status feedback.
pub enum HotkeyOutcome {
    Typed { label: String },
    NoAutoProfile,
    Error(String),
}

/// Owns the OS hotkey registration. Dropping it unregisters the combo.
pub struct HotkeyService {
    manager: GlobalHotKeyManager,
    hotkey: HotKey,
    binding: HotkeyBinding,
    /// Worker results (typed / error), drained by the UI when visible.
    pub outcomes: Receiver<HotkeyOutcome>,
    /// Shared, mutable settings the background poll thread reads.
    shared: Arc<Mutex<HotkeyShared>>,
    /// Signals the background poll thread to stop (on drop).
    stop: Arc<AtomicBool>,
}

struct HotkeyShared {
    transport: Interface,
    append_enter: bool,
}

impl HotkeyService {
    /// Register `binding` as a global Auto-OTP hotkey.
    pub fn new(
        binding: HotkeyBinding,
        transport: Interface,
        append_enter: bool,
    ) -> Result<Self, String> {
        if !binding.has_modifier() {
            return Err("choose at least one modifier (Ctrl / Alt / Shift / Super)".into());
        }
        let manager = GlobalHotKeyManager::new().map_err(|e| e.to_string())?;
        let hotkey = binding.to_hotkey();
        let hotkey_id = hotkey.id();
        manager.register(hotkey).map_err(|e| {
            format!(
                "could not register {} — another app may already own it; \
                 try a different combination ({e})",
                binding.label()
            )
        })?;
        let (tx, rx) = mpsc::channel();
        let shared = Arc::new(Mutex::new(HotkeyShared {
            transport,
            append_enter,
        }));
        let stop = Arc::new(AtomicBool::new(false));

        // Poll the global hotkey channel on a dedicated thread so it works even
        // when the window is hidden/minimized and eframe has stopped calling
        // update(). The global-hotkey event receiver is a process-global
        // channel, so draining it here is correct regardless of window state.
        {
            let shared = shared.clone();
            let stop = stop.clone();
            let outcomes_tx = tx.clone();
            std::thread::spawn(move || {
                let receiver = GlobalHotKeyEvent::receiver();
                while !stop.load(Ordering::Relaxed) {
                    // Block briefly for an event so we don't busy-spin.
                    match receiver.recv_timeout(std::time::Duration::from_millis(150)) {
                        Ok(event) => {
                            if event.id == hotkey_id && event.state == HotKeyState::Pressed {
                                let (transport, append_enter) = {
                                    let s = shared.lock().unwrap();
                                    (s.transport, s.append_enter)
                                };
                                let outcome = read_and_type(transport, append_enter);
                                let _ = outcomes_tx.send(outcome);
                            }
                        }
                        // Timeout: loop to re-check the stop flag.
                        // Disconnected: the global sender is gone; stop.
                        Err(e) => {
                            if e.is_disconnected() {
                                break;
                            }
                        }
                    }
                }
            });
        }

        Ok(HotkeyService {
            manager,
            hotkey,
            binding,
            outcomes: rx,
            shared,
            stop,
        })
    }

    pub fn label(&self) -> String {
        self.binding.label()
    }

    pub fn set_transport(&mut self, t: Interface) {
        if let Ok(mut s) = self.shared.lock() {
            s.transport = t;
        }
    }

    /// No-op kept for API compatibility: polling now happens on a dedicated
    /// thread (see `new`), so the UI no longer needs to call this.
    pub fn poll(&self) {}
}

/// Find the `[A]` profile, read its live code, and type it.
fn read_and_type(transport: Interface, append_enter: bool) -> HotkeyOutcome {
    let mut session = match OtpSession::open(transport, false) {
        Ok(s) => s,
        Err(e) => return HotkeyOutcome::Error(e.to_string()),
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Locate the Auto-OTP profile by its [A] issuer tag.
    let entries = match session.enumerate(now) {
        Ok(e) => e,
        Err(e) => return HotkeyOutcome::Error(e.to_string()),
    };
    let Some(target) = entries.into_iter().find(|e| e.app_name.contains(AUTO_TAG)) else {
        return HotkeyOutcome::NoAutoProfile;
    };

    // Prefer the code the enumerate already returned (TOTP, no touch). For a
    // touch-required entry, do a targeted read (the user must touch the key).
    let code = match target.code.clone() {
        Some(c) => c,
        None => match session.read_entry(now, &target.app_name, &target.account_name) {
            Ok(e) => match e.code {
                Some(c) => c,
                None => return HotkeyOutcome::Error("key returned no code".into()),
            },
            Err(e) => return HotkeyOutcome::Error(e.to_string()),
        },
    };

    if let Err(e) = type_code(&code, append_enter) {
        return HotkeyOutcome::Error(e);
    }

    let label = if target.app_name.is_empty() {
        target.account_name
    } else {
        format!("{}:{}", target.app_name, target.account_name)
    };
    HotkeyOutcome::Typed { label }
}

/// Inject the code as keystrokes into the focused window.
fn type_code(code: &str, append_enter: bool) -> Result<(), String> {
    use enigo::{Direction, Enigo, Key, Keyboard, Settings};
    let mut enigo = Enigo::new(&Settings::default()).map_err(|e| e.to_string())?;

    // Brief pause so the user's physical hotkey keys begin to release before we
    // synthesize input.
    std::thread::sleep(std::time::Duration::from_millis(60));

    // Explicitly release the hotkey modifiers. When the hotkey is pressed
    // rapidly, the physical Ctrl/Alt/Shift/Meta can still be held while we
    // inject Enter — turning it into Ctrl+Enter / Alt+Enter, which most fields
    // ignore (this is why only the final, fully-released press submitted). We
    // force these up first so both the digits and the Enter are unmodified.
    for k in [Key::Control, Key::Alt, Key::Shift, Key::Meta] {
        let _ = enigo.key(k, Direction::Release);
    }

    // Type the digits.
    enigo.text(code).map_err(|e| e.to_string())?;

    if append_enter {
        // Let all digit keystrokes land before Enter, and release modifiers
        // again in case the user is still leaning on the hotkey.
        std::thread::sleep(std::time::Duration::from_millis(40));
        for k in [Key::Control, Key::Alt, Key::Shift, Key::Meta] {
            let _ = enigo.key(k, Direction::Release);
        }
        enigo
            .key(Key::Return, Direction::Click)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

impl Drop for HotkeyService {
    fn drop(&mut self) {
        // Stop the background poll thread, then unregister the combo.
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.manager.unregister(self.hotkey);
    }
}
