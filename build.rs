//! Build script: on Windows, embed `assets/icon.ico` into the executables so
//! they show a proper icon in Explorer, the taskbar, and Alt-Tab.
//!
//! The icon is optional — if `assets/icon.ico` is absent the build proceeds
//! without an embedded icon (the app still sets a window/tray icon at runtime
//! from `assets/icon.png` when present). Drop a multi-resolution `.ico`
//! (16/32/48/256 px) at `assets/icon.ico` to brand the binary.

fn main() {
    // Re-run if the icon changes.
    println!("cargo:rerun-if-changed=assets/icon.ico");

    #[cfg(target_os = "windows")]
    {
        if std::path::Path::new("assets/icon.ico").exists() {
            let mut res = winresource::WindowsResource::new();
            res.set_icon("assets/icon.ico");
            // A couple of nice-to-have metadata fields shown in the file's
            // Properties → Details tab.
            res.set("ProductName", "T2 TOTP Authenticator");
            res.set("FileDescription", "T2 TOTP Authenticator");
            if let Err(e) = res.compile() {
                println!("cargo:warning=could not embed Windows icon: {e}");
            }
        } else {
            println!(
                "cargo:warning=assets/icon.ico not found; building without an embedded icon"
            );
        }
    }
}
