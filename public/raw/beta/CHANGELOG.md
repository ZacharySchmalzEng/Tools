# Changelog — Linux Automated Deployment & Provisioning Tool (Beta Suite)

All notable security updates, defect resolutions, and feature enhancements for the modular **v3.x Beta Suite** (`Linux-Deployment-Tool.sh`, `lib/common.sh`, and `modules/mod-*.sh`) are documented in this file.

> [!NOTE]
> For historical release notes covering the monolithic **v1.x–v2.x Production Suite**, see **[`../CHANGELOG.md`](../CHANGELOG.md)**.

---

## [v3.1.0-beta] — SecOps Audit, SSH Config Rollback Guards & Cross-Distro Dependency Sweep

### Feature Enhancements
- **OpenSSH Pre-Flight Validation & Automatic Rollback (`backup_sshd_config` & `validate_and_restart_sshd`):** Added transaction rollback protection to `Beta/lib/common.sh` and wired it into `mod-harden.sh`, `mod-harden-adv.sh`, and `mod-ssh.sh`. Saves a `0600` backup before mutating `/etc/ssh/sshd_config`, validates syntax via `sshd -t -f /etc/ssh/sshd_config` (creating `/run/sshd` if absent on Debian/Ubuntu), and automatically restores the known-good backup on failure to prevent remote lockout.
- **Atomic Download & Shebang Verification Across All Standalone Bootstraps:** Hardened `bootstrap_common_library` in `Beta/Linux-Deployment-Tool.sh` and the standalone `lib/common.sh` bootstrap block in all 11 child modules (`Beta/modules/mod-*.sh`) to download to a temporary file (`${COMMON_PATH}.tmp.$$`), verify a valid `#!` script header (`head -n 1 | grep -q "^#!"`), set `chmod 0755`, and atomically `mv -f` into place before sourcing as `root`.
- **Deprecation Registry Input Sanitization (`DEPRECATED_MODULES_REGISTRY`):** Enforced strict allowlist regex validation on dynamic variable names (`^RUN_[A-Z0-9_]+$`) and module filenames (`^mod-[a-z0-9-]+\.sh$`) across `resolve_deprecated_flags`, `check_deprecated_local_modules`, `write_deprecated_module_stub`, and `handle_deprecated_module_stub`.
- **Expanded Base Prerequisite Bootstrap (`bootstrap_prerequisites`):** Added automatic verification and installation for `sha256sum` (`coreutils`), `awk` (`gawk`), and `gpg` (`gnupg2` on RPM/openSUSE, `gnupg` on Debian/Ubuntu/Arch/SteamOS).

### Defect Resolutions & Bug Fixes
- **Fixed Always-True `if ... || true` Pipeline Conditions:** Resolved `if flatpak list 2>/dev/null | grep -qi "discord" || true; then` in `mod-gaming.sh` and `if ss -lt | grep -q ssh || true; then` in `mod-ssh.sh` (`ss -lt 2>/dev/null | grep -qE '(:ssh|:22)\b'`) so false positives no longer mask missing Flatpaks or non-listening SSH daemons.
- **Fixed Fedora 41+ / DNF5 `dnf5-plugin-automatic` Short-Circuit (`mod-harden.sh`):** Consolidated `pkg_install dnf-automatic dnf5-plugin-automatic` into a single transaction so DNF's `--skip-unavailable` flag installs whichever automatic patching plugin exists on the host's Fedora release instead of short-circuiting the fallback on exit code `0`.
- **Fixed Cross-Distro Package Identifiers (`mod-gaming.sh` & `lib/common.sh`):** Updated `PRE_PKGS` in `mod-gaming.sh` from `snap` to `snapd` and added cross-distro mappings in `resolve_package_name()` (`snap` -> `snapd`, `prusa-slicer` -> `PrusaSlicer` on openSUSE).

---

## [v3.0.2-beta] — Discord Wrapped into Gaming, Deprecation Handlers & DNF5 Mirror Failover Hardening

### Feature Enhancements
- **Discord Module Wrapped into Gaming (`mod-gaming.sh`):** Merged Discord provisioning and RPM/Flatpak transition logic directly into `Beta/modules/mod-gaming.sh` (native `discord` RPM via RPM Fusion on standard Fedora/Nobara/RHEL; `com.discordapp.Discord` via Flathub on Atomic/Bazzite/SteamOS and non-RPM distros). Removed standalone `mod-discord.sh` from the repository and `Linux-Deployment-Tool-Beta.tar.gz`, and hid `--discord` from `--help` while retaining legacy CLI parser support.
- **Module Deprecation & Redirect Handler Framework (`lib/common.sh`):** Added `DEPRECATED_MODULES_REGISTRY` (`--discord -> --gaming`), `resolve_deprecated_flags` (`[y]` redirect / `[a]` abort & run local script as-is / `[s]` skip), `check_deprecated_local_modules` (`[r]` remove / `[s]` stub / `[k]` keep), and `handle_deprecated_module_stub`.
- **Explicit "Abort Updates & Run As-Is" Control (`check_and_prompt_github_updates`):** Expanded the interactive GitHub startup update prompt into a 3-way choice (`[y]` Update now, `[n]` Abort updates & run as-is, `[q]` Quit).

### Defect Resolutions & Bug Fixes
- **DNF5 Mirror Failover & Metadata Skew Hardening (Fedora / Rawhide):** Tightened `DNF_RETRY_OPTIONS` to `--setopt=retries=10 --setopt=timeout=15 --setopt=minrate=1000` so `libdnf5` drops unreachable or stalled mirrors (`Curl error (7)`) within 15 seconds, and added automatic `dnf clean expire-cache` + `--refresh` retry recovery to `pkg_install` and `update_system` when tier-2 mirrors return `Status code: 404`.

---

## [v3.0.1-beta] — Relaxed Ambient Umask, Non-Root Log Permissions & GitHub Self-Update Engine

### Feature Enhancements
- **Non-Root Readable & Writable Permissions (`+rw`):** Relaxed ambient `umask` to `0022`, configured `InstallerLogs/` to `0777`, set generated execution transcripts (`InstallerLogs/installer_log_*.log`) to `0666` (`rw-rw-rw-`), and set `lib/` and `modules/` scripts to `0755` (`rwxr-xr-x`).
- **Automated GitHub Update Detection & Self-Updating:** Added startup SHA-256 update checking against GitHub (`check_remote_script_update` and `apply_script_update`) for `Linux-Deployment-Tool.sh`, `lib/common.sh`, and active `modules/mod-*.sh` scripts, with `--no-update-check` bypass support.

### Defect Resolutions & Bug Fixes
- **Main Branch Raw URL Fallback:** Updated default `GITHUB_RAW_BASE` across the main runner, shared library, and child modules to `https://raw.githubusercontent.com/ZacharySchmalzEng/Tools/main/Linux/Provisioning/Linux-Deployment-Tool/Beta`, resolving HTTP 404 errors during isolated single-runner `curl` executions.

---

## [v3.0.0-beta] — Modular On-Demand Architecture & Standalone Child Scripts

### Feature Enhancements
- **Top-of-Beta Modular Runner:** Positioned `Linux-Deployment-Tool.sh` at the top of `./Beta` alongside `CHANGELOG.md`, `README.md`, `lib/`, and `modules/` for flat tarball extraction (`Linux-Deployment-Tool-Beta.tar.gz`).
- **Decomposed Child Module Suite:** Split monolithic routines into standalone child module scripts under `Beta/modules/` (`mod-update.sh`, `mod-apps.sh`, `mod-devapps.sh`, `mod-sysadmin.sh`, `mod-cyber.sh`, `mod-maker.sh`, `mod-creators.sh`, `mod-harden.sh`, `mod-harden-adv.sh`, `mod-ssh.sh`, and `mod-gaming.sh`).
- **Shared Core Library (`Beta/lib/common.sh`):** Centralized multi-distro detection (`detect_distro`), package routing (`pkg_install`), system updates (`update_system`), SteamOS read-only traps, configuration mutators (`set_sshd_option`, `set_ini_option`), and standalone child bootstrapping (`init_standalone_module`).
- **Independent & Orchestrated Execution:** Enabled every child module to run independently (`sudo ./modules/mod-gaming.sh --rebuild -y`) or through the main orchestrator (`sudo ./Linux-Deployment-Tool.sh --gaming -y`) with lazy on-demand GitHub synchronization.
