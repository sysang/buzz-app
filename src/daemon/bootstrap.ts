import { installDaemonShim } from "./shim";

// The daemon's checked entry page carries this marker; the desktop webview does
// not. This module is ordered before /src/main.tsx by index.html, and completes
// installation synchronously before either module's dependency graph evaluates.
if (document.querySelector('meta[name="buzz-web-token"]')) installDaemonShim();
