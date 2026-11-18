#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // The daemon entry is the same binary: `buzz --daemon` runs the host with
    // zero webview windows and a long-lived event loop (WDA-S-01.1). Without
    // the flag the desktop application runs exactly as before.
    if std::env::args_os().any(|arg| arg == "--daemon") {
        buzz_foundation_lib::run_daemon();
    } else {
        buzz_foundation_lib::run();
    }
}
