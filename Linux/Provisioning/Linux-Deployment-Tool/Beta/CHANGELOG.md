# Changelog — Linux-Deployment-Tool (Beta Channel 3.x)

This document tracks all release notes, architectural enhancements, security updates, and bug fixes for the **3.x Beta Modular Suite** located in this directory (`Linux/Provisioning/Linux-Deployment-Tool/Beta/`).

For historical release notes for versions `1.0` through `2.1` (the monolithic production channel), see the main changelog at **`../CHANGELOG.md`**.

---

## [v3.0.1-beta] — Relaxed Ambient Umask & Non-Root Log Permissions

### Security & Operational Enhancements
- **Non-Root Readable & Writable Permissions (+rw):**
  - Relaxed initial ambient `umask 077` to standard `umask 0022` across `Beta/Linux-Deployment-Tool.sh` and `Beta/lib/common.sh`.
  - Configured `InstallerLogs/` directory to `0777` permissions.
  - Set generated execution transcripts (`InstallerLogs/installer_log_*.log`) to `0666` (`rw-rw-rw-`) permissions. Non-root desktop sessions, IDEs, and local user accounts can now read, tail, or append to logs without requiring `sudo` or administrative elevation.
  - Set library and child module directories (`lib/`, `modules/`) and cached scripts to `0755` (`rwxr-xr-x`), maintaining administrative execution (`+x`) while allowing all system users to read the code without elevation.

### Defect Resolutions & GitHub Raw Routing
- **Main Branch Raw URL Fallback:** Updated the default `GITHUB_RAW_BASE` repository URL across the main runner, shared library, and all 12 child modules to target the active `main` branch:
  `https://raw.githubusercontent.com/ZacharySchmalzEng/Tools/main/Linux/Provisioning/Linux-Deployment-Tool/Beta`
  resolving HTTP 404 errors during isolated single-runner curl executions.
- **Automated GitHub Update Detection & Self-Updating:** Added startup update checking against GitHub for the main runner (`Linux-Deployment-Tool.sh`), shared core library (`lib/common.sh`), and all invoked child modules (`modules/mod-*.sh`). Uses SHA-256 hash comparison between local and remote raw files, and interactively prompts the user (`y/n`) with the list of candidate updates before downloading and applying them. Seamlessly restarts execution (`exec "$0" "$@"`) if the main runner itself is updated. Can be bypassed using `--no-update-check`.

---

## [v3.0.0-beta] — Modular On-Demand Architecture & Standalone Child Scripts

### Architecture & Feature Enhancements
- **Top-of-Beta Modular Runner:** Positioned `Linux-Deployment-Tool.sh` at the top of `./Beta` alongside `CHANGELOG.md`, `README.md`, `lib/`, and `modules/` for flat tarball extraction (`Linux-Deployment-Tool-Beta.tar.gz`).
- **Decomposed Child Module Suite:** Split monolithic routines into 12 standalone child module scripts under `Beta/modules/`:
  - `mod-update.sh` (`--update`)
  - `mod-apps.sh` (`--apps`)
  - `mod-devapps.sh` (`--devapps`)
  - `mod-sysadmin.sh` (`--sysadmin`)
  - `mod-cyber.sh` (`--cyber`)
  - `mod-maker.sh` (`--maker`)
  - `mod-creators.sh` (`--creators`)
  - `mod-harden.sh` (`--harden`)
  - `mod-harden-adv.sh` (`--harden-advanced`)
  - `mod-ssh.sh` (`--ssh`, `--2fa`)
  - `mod-discord.sh` (`--discord`)
  - `mod-gaming.sh` (`--gaming`)
- **Shared Core Library (`Beta/lib/common.sh`):** Centralized multi-distro detection (`detect_distro`), package routing (`pkg_install`), system updates (`update_system`), SteamOS read-only traps, configuration mutators (`set_sshd_option`, `set_ini_option`), and standalone child bootstrapping (`init_standalone_module`).
- **Independent & Orchestrated Execution:** Every child module can run independently (`sudo ./modules/mod-gaming.sh --rebuild -y`) or through the main orchestrator (`sudo ./Linux-Deployment-Tool.sh --gaming -y`).
- **Lazy On-Demand GitHub Sync:** Missing child modules are downloaded from GitHub only when their matching CLI flags are invoked, caching them locally in `./modules/` for subsequent offline execution.
- **Dedicated Beta Changelog:** Established this `Beta/CHANGELOG.md` to track all 3.x modular development separately from the production 2.x changelog.
