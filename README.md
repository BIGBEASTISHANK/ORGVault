# ORGVault V1

> [!Important]
> Developement of this project has been transfered to [BBICorporation/ORGVault](https://github.com/BBICorporation/ORGVault)

## Project Overview

The Next-Gen Desktop Based Secure Data Vault is a cross-platform desktop application designed to provide organizations with a highly secure, encrypted solution for storing, sharing, and synchronizing sensitive documents across multiple devices within a local area network (LAN). The solution ensures confidentiality, controlled access, offline usability, and comprehensive audit logging while defending against ransomware-style attacks through immutable backups and version control.

---

## Key Features

- **Cross-Platform Support:** Built with Rust, the application runs on Linux (primary demo environment) with potential portability to Windows and macOS.
- **Strong Encryption:** All stored documents are encrypted using industry-standard AES-256. SHA-256 hashes are used for file integrity checks.
- **Two-Way Synchronization:** Seamless encrypted synchronization of files between local desktop clients and a central backend server over LAN.
- **Offline Functionality:** Full access to stored documents is available when offline. Changes are auto-synced once connectivity is restored.
- **Role-Based and Group-Based Access Control:** Fine-grained permission settings for sharing documents securely among different users and groups.
- **Audit Trails:** All file accesses, modifications, sharing actions, and synchronization events are logged securely and viewable in-app.
- **In-App Notifications:** Users receive real-time popup alerts for document shares, updates, and important system events.
- **Ransomware Protection:** Incorporates version-controlled document backup and immutable storage to defend against tampering or deletion.
- **Lightweight & Easy Deployment:** The application is lightweight and designed for simple deployment in organizational intranets using Rust tooling.

---

## Architecture Overview

- **UI Layer:** Developed in Rust using the Tauri framework, providing a responsive desktop interface including file management, permissions setup, audit log viewer, and notifications.
- **Backend Server:** Implemented in Rust (using Actix-web or Rocket frameworks) hosted on a dedicated Linux machine; manages synchronization requests, conflict resolution, authentication, and centralized encrypted storage.
- **Local Storage:** Encrypted SQLite database (with SQLCipher or encryption wrappers) manages metadata, audit logs, and file encryption keys alongside document storage.
- **Networking:** Sync performed via secure RESTful APIs over LAN using asynchronous Rust libraries (Tokio/async-std) for performance.

---

## System Requirements

- **Development Environment:** Linux-based laptops for UI and backend development.
- **Deployment Environment:** Linux server for backend hosting; clients run on Linux desktops.
- **Networking:** Local area network with fixed IPs or mDNS for device discovery.

---

## Setup and Usage

### Prerequisites

- Rust toolchain installed (rustc, cargo)
- SQLite with encryption support
- LAN connectivity among devices

### Usage

- Launch the backend server on the designated server laptop.
- Start the client on user laptops, which will connect to the backend over LAN.
- Use the application UI to add, encrypt, and manage files.
- Share documents with users or groups by assigning appropriate permissions.
- Monitor audit logs and receive notifications within the client app.
- Work offline as needed; all changes will sync once back online.

---

## Security Considerations

- **Encryption:** Uses AES-256 for all file content encryption. Keys are securely managed and never stored in plaintext.
- **Data Integrity:** SHA-256 hashes verify file integrity during sync.
- **Access Control:** Strict role-based access ensures only authorized users can view or modify documents.
- **Ransomware Defense:** Versioning and immutable backups guard against malicious data loss.
- **Network Security:** Sync communications are limited to LAN and protected by authentication to prevent unauthorized access.

---

## Future Enhancements

- Extend cross-platform support to Windows and macOS.
- Add more granular user activity monitoring and alerting.
- Integrate desktop notifications and advanced reporting dashboards.
