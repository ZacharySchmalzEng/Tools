## 🪟 Windows (Windows 10/11 Pro)

* **/Windows/Backups/**
    * `deploy-restic-gdrive.ps1`: Deploys a self-contained, automated Restic backup architecture targeting Google Drive. Leverages native Windows VSS (`--use-fs-snapshot`) via a SYSTEM-context Scheduled Task to safely snapshot locked files. Features a randomized execution delay to prevent API rate-limiting and repository locking in multi-host environments.

* **/Windows/Data_Management/**
    * `ProfileMerge.ps1`: Heuristic discovery and deduplication engine for resolving cross-OS user profile collisions on shared NTFS volumes. Utilizes SHA-256 cryptographic hashing to identify true duplicates and enforces a declarative CSV state-plan architecture for safe, idempotent manual review prior to execution.

* **/Windows/Provisioning/**
    * `/Windows-Deployment-Tool/`: A modular, flag-based deployment framework for fresh OS installations. Executes telemetry hardening, system debloating, and dynamic software stack provisioning (e.g., `-DevApps`, `-Maker`, `-Cyber`) utilizing `winget` and native installers. Supports automated teardown via a global `-Uninstall` modifier.
    * `Deploy-OSMaintenanceTask.ps1`: Registers an idempotent Scheduled Task for automated, monthly OS servicing. Utilizes a fileless execution architecture by embedding a Base64-encoded payload directly into the task XML
    Executes conditional NTFS auditing (`chkdsk`), system file verification (`sfc`), and component store cleanup (`DISM`).

> **Security Note:** Most provisioning and backup scripts require execution via elevated sessions (root or Administrator) to modify system states, register scheduled tasks, or invoke VSS. Review all source code prior to execution.