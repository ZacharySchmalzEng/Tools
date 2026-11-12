# Changelog — Linux-Deployment-Tool (Beta Channel 3.x)

This document tracks all release notes, architectural enhancements, security updates, and bug fixes for the **3.x Beta Modular Suite** located in this directory (`Linux/Provisioning/Linux-Deployment-Tool/Beta/`).

For historical release notes for versions `1.0` through `2.1` (the monolithic production channel), see the main changelog at **`../CHANGELOG.md`**.

---

## [v3.1.0-beta] — SecOps Audit, SSH Config Rollback Guards & Cross-Distro Dependency Sweep

### Security Operations (SecOps) Hardening
- **OpenSSH Pre-Flight Validation & Automatic Rollback (`backup_sshd_config` & `validate_and_restart_sshd`):**
  - Added transaction rollback protection to `Beta/lib/common.sh` and wired it into `mod-harden.sh`, `mod-harden-adv.sh`, and `mod-ssh.sh`.
  - Before mutating `/etc/ssh/sshd_config`, the script saves a `0600` backup (`.ldt.bak.$$`), applies changes, and tests syntax and directives with `sshd -t -f /etc/ssh/sshd_config` (creating `/run/sshd` if absent on Debian/Ubuntu).
  - If validation passes, the backup is cleaned up and `$SSH_SERVICE` is restarted; if validation fails, the known-good backup is automatically restored to prevent remote administrator lockout.
- **Atomic Download & Shebang Verification Across All Standalone Bootstraps:**
  - Hardened `bootstrap_common_library` in `Beta/Linux-Deployment-Tool.sh` and the standalone `lib/common.sh` bootstrap block in all 11 child modules (`Beta/modules/mod-*.sh`) to download to a temporary file (`${COMMON_PATH}.tmp.$$`), verify a valid `#!` script header (`head -n 1 | grep -q "^#!"`) to reject captive-portal HTML or truncated payloads, set `chmod 0755`, and atomically `mv -f` into place before sourcing as `root`.
- **Deprecation Registry Input Sanitization (`DEPRECATED_MODULES_REGISTRY`):**
  - Enforced strict allowlist regex validation on dynamic variable names (`^RUN_[A-Z0-9_]+$`) and module filenames (`^mod-[a-z0-9-]+\.sh$`) across `resolve_deprecated_flags`, `check_deprecated_local_modules`, `write_deprecated_module_stub`, and `handle_deprecated_module_stub` to prevent arbitrary variable mutation or path traversal via `LDT_DEPRECATED_MODULES`.

### Shell Logic & Cross-Distribution Dependency Sweep
- **Fixed Always-True `if ... || true` Pipeline Conditions:**
  - Resolved `if flatpak list 2>/dev/null | grep -qi "discord" || true; then` in `mod-gaming.sh` (which previously evaluated to `true` even when Flatpak Discord was not installed).
  - Resolved `if ss -lt | grep -q ssh || true; then` in `mod-ssh.sh` to accurately check `ss -lt 2>/dev/null | grep -qE '(:ssh|:22)\b'` so non-listening daemons are properly flagged.
- **Fixed Fedora 41+ / DNF5 `dnf5-plugin-automatic` Short-Circuit (`mod-harden.sh`):**
  - Consolidated `pkg_install dnf-automatic dnf5-plugin-automatic` into a single transaction so DNF's `--skip-unavailable` flag installs whichever automatic patching plugin exists on the host's Fedora release instead of short-circuiting the fallback on exit code `0`.
- **Fixed RPM Snap Package Identifier (`mod-gaming.sh` & `lib/common.sh`):**
  - Updated `PRE_PKGS` in `mod-gaming.sh` from `snap` to `snapd` and added cross-distro mappings in `resolve_package_name()` (`snap` -> `snapd`, `prusa-slicer` -> `PrusaSlicer` on openSUSE).
- **Expanded Base Prerequisite Bootstrap (`bootstrap_prerequisites`):**
  - Added automatic verification and installation for `sha256sum` (`coreutils`), `awk` (`gawk`), and `gpg` (`gnupg2` on RPM/openSUSE, `gnupg` on Debian/Ubuntu/Arch/SteamOS) so SHA-256 update checks and Microsoft PowerShell repository GPG dearmoring never fail on minimal installations.

---

## [v3.0.2-beta] — Discord Wrapped into Gaming, Deprecation Handlers & DNF5 Mirror Failover Hardening

### Architecture & Module Consolidation
- **Discord Module Wrapped into Gaming (`mod-gaming.sh`):**
  - Merged Discord provisioning and RPM/Flatpak transition logic directly into `Beta/modules/mod-gaming.sh`:
    - **Standard RPM (Fedora / Nobara / RHEL):** Uninstalls any existing Flatpak Discord and installs the native `discord` RPM package using the RPM Fusion repositories already configured by `mod-gaming.sh`.
    - **Atomic / Bazzite / SteamOS & Non-RPM Distros:** Installs and maintains `com.discordapp.Discord` via Flathub for immutable filesystem safety.
  - Removed standalone `mod-discord.sh` from the repository and `Linux-Deployment-Tool-Beta.tar.gz`, reducing the modular suite from 12 to 11 child scripts.
  - Hidden `--discord` from the `--help` usage menu while keeping it active in the CLI parser so legacy invocations are caught by the deprecation handler.
- **Module Deprecation & Redirect Handler Framework (`lib/common.sh`):**
  - Added a centralized `DEPRECATED_MODULES_REGISTRY` (`flag|old_mod|new_flag|new_mod|old_var|new_var|reason`) with `--discord -> --gaming` active.
  - `resolve_deprecated_flags`: Warns when a deprecated CLI flag is passed and interactively prompts the user to `[y]` redirect to the replacement module (`--gaming`), `[a]` **abort redirection and run a local `mod-discord.sh` as-is** (if present on disk), or `[s]` skip the module. In `--unattended` or `-y` mode, automatically logs a warning and redirects to `--gaming`.
  - `check_deprecated_local_modules`: Scans `./modules/` for retired module files from earlier downloads and prompts the user to `[r]` remove the stale file, `[s]` replace it with a lightweight `0755` redirect stub, or `[k]` keep and run the local script as-is.
  - `handle_deprecated_module_stub`: Allows retired standalone module stubs to warn and forward execution to their replacement module when run directly (`sudo ./modules/mod-<name>.sh`).

### Update Control & Package Manager Resilience
- **Explicit "Abort Updates & Run As-Is" Control (`check_and_prompt_github_updates`):**
  - Expanded the interactive GitHub startup update prompt into a 3-way choice:
    - `[y]` **Update now** — Applies updates (`0755`) and restarts the main runner (`exec "$0" "$@"`) if updated.
    - `[n]` **Abort updates & run as-is** — Cleans up temporary `.chk` candidate files and runs the existing local scripts unmodified.
    - `[q]` **Quit** — Exits cleanly before making any system changes.
- **DNF5 Mirror Failover & Metadata Skew Hardening (Fedora / Rawhide):**
  - Tightened `DNF_RETRY_OPTIONS` from `--setopt=timeout=60` to `--setopt=retries=10 --setopt=timeout=15 --setopt=minrate=1000` so `libdnf5` drops unreachable or stalled mirrors (`Curl error (7)`) within 15 seconds instead of waiting up to a minute per mirror.
  - Added automatic `dnf clean expire-cache` + `--refresh` retry recovery to `pkg_install` and `update_system` in `lib/common.sh` (and ensured `refresh_package_cache` runs before `dnf group upgrade core` in `mod-gaming.sh`) to recover when tier-2 Fedora mirrors return `Status code: 404` due to mirror propagation lag.

---

## [v3.0.1-beta] — Relaxed Ambient Umask, Non-Root Log Permissions & GitHub Self-Update Engine

### Security & Operational Enhancements
- **Non-Root Readable & Writable Permissions (+rw):**
  - Relaxed initial ambient `umask 077` to standard `umask 0022` across `Beta/Linux-Deployment-Tool.sh` and `Beta/lib/common.sh`.
  - Configured `InstallerLogs/` directory to `0777` permissions.
  - Set generated execution transcripts (`InstallerLogs/installer_log_*.log`) to `0666` (`rw-rw-rw-`) permissions. Non-root desktop sessions, IDEs, and local user accounts can now read, tail, or append to logs without requiring `sudo` or administrative elevation.
  - Set library and child module directories (`lib/`, `modules/`) and cached scripts to `0755` (`rwxr-xr-x`), maintaining administrative execution (`+x`) while allowing all system users to read the code without elevation.

### Defect Resolutions & GitHub Raw Routing
- **Main Branch Raw URL Fallback:** Updated the default `GITHUB_RAW_BASE` repository URL across the main runner, shared library, and child modules to target the active `main` branch:
  `https://raw.githubusercontent.com/ZacharySchmalzEng/Tools/main/Linux/Provisioning/Linux-Deployment-Tool/Beta`
  resolving HTTP 404 errors during isolated single-runner curl executions.
- **Automated GitHub Update Detection & Self-Updating:** Added startup update checking against GitHub (`check_remote_script_update` and `apply_script_update`) for the main runner (`Linux-Deployment-Tool.sh`), shared core library (`lib/common.sh`), and all invoked child modules (`modules/mod-*.sh`) using SHA-256 hash comparison. Can be bypassed via `--no-update-check`.

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
