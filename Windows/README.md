## 🪟 Windows (Windows 10/11 Pro)

* **/Windows/Backups/**
    * `deploy-restic-gdrive.ps1`: Deploys a self-contained, automated Restic backup architecture targeting Google Drive. [cite_start]Leverages native Windows VSS (`--use-fs-snapshot`) via a SYSTEM-context Scheduled Task to safely snapshot locked files[cite: 4034, 4035]. [cite_start]Features a randomized execution delay to prevent API rate-limiting and repository locking in multi-host environments[cite: 4037, 4038].

* **/Windows/Data_Management/**
    * `ProfileMerge.ps1`: Heuristic discovery and deduplication engine for resolving cross-OS user profile collisions on shared NTFS volumes. Utilizes SHA-256 cryptographic hashing to identify true duplicates [cite: 2491] and enforces a declarative CSV state-plan architecture for safe, idempotent manual review prior to execution[cite: 2521, 2526].

* **/Windows/Provisioning/**
    * `/Windows-Deployment-Tool/`: A modular, flag-based deployment framework for fresh OS installations. Executes telemetry hardening, system debloating, and dynamic software stack provisioning (e.g., `-DevApps`, `-Maker`, `-Cyber`) utilizing `winget` and native installers[cite: 3114, 3159]. Supports automated teardown via a global `-Uninstall` modifier[cite: 3114].
    * [cite_start]`Deploy-OSMaintenanceTask.ps1`: Registers an idempotent Scheduled Task for automated, monthly OS servicing[cite: 2278, 2320]. [cite_start]Utilizes a fileless execution architecture by embedding a Base64-encoded payload directly into the task XML[cite: 2419, 2421]. [cite_start]Executes conditional NTFS auditing (`chkdsk`), system file verification (`sfc`), and component store cleanup (`DISM`)[cite: 2284, 2285, 2286].

> **Security Note:** Most provisioning and backup scripts require execution via elevated sessions (root or Administrator) to modify system states, register scheduled tasks, or invoke VSS. Review all source code prior to execution.