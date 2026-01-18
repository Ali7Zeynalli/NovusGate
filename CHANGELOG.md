# Changelog

All notable changes to this project will be documented in this file.

## [1.1.0] - 2026-01-18
### Added
- **Web Terminal**: Interactive SSH terminal directly in the browser using `xterm.js` and `socket.io`.
- **Server Dashboard**: Real-time server monitoring (CPU, RAM, Disk, Uptime) with auto-polling.
- **SSH Key Support**: Ability to add servers using SSH Private Keys (PEM format).
- **Passphrase Support**: Support for encrypted SSH keys (password-protected keys).
- **Quick Actions**: Compact buttons for common server tasks (Terminal, Credentials, Updates).
- **Version Indicator**: Added "v1.1" label to the footer.

### Changed
- **Rebranding**: Renamed "Installer" to **"NovusGate Center"** across the UI.
- **UI Improvements**: Modernized the "Add Server" modal and "Server Detail" view.
- **Backend**: Refactored `server.js` to support WebSocket connections (Socket.IO).

### Fixed
- **Duplicate UI Elements**: User interface cleanup (removed duplicate buttons).
- **SSH Connection**: Improved error handling for SSH connections.

## [1.0.0] - 2025-12-30
### Added
- Initial Release of NovusGate Installer.
- Basic SSH Password Authentication.
- Docker Deployment Automation.
- WireGuard VPN Setup Automation.
