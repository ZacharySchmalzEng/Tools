# Hotfix v2.0.1: OrcaSlicer Flatpak Migration & DNF Automatic Hardening Plan

A targeted remediation plan for Hotfix Release `v2.0.1` to resolve two critical deployment defects: the Flathub OrcaSlicer package ID migration failure and the fatal `sed: can't read /etc/dnf/automatic.conf` crash on RPM/Fedora systems.

---

### User Review & Critical Decisions

> [!IMPORTANT]
> **Confirmed Remediation Decisions (from Phase 1 Clarifications)**:
> 1. **OrcaSlicer Flathub ID Migration**:
>    - Migrate the primary Flatpak identifier from `com.softfever.OrcaSlicer` to `com.orcaslicer.OrcaSlicer` (matching Flathub's upstream namespace transition).
>    - Add dynamic fallback logic: if `com.orcaslicer.OrcaSlicer` fails or is not found in an outdated cache, attempt `com.softfever.OrcaSlicer`.
> 2. **DNF Automatic Configuration & DNF5 Compatibility**:
>    - Eliminate the brittle assumption that `/etc/dnf/automatic.conf` exists prior to `sed` invocation.
>    - If `/etc/dnf/automatic.conf` does not exist (or in modern Fedora 41 DNF5 environments where `dnf-automatic` has been transitioned), automatically generate the required configuration directory (`/etc/dnf`) and write an idempotent, secure baseline:
>      ```ini
>      [commands]
>      upgrade_type = security
>      download_updates = yes
>      apply_updates = yes
>      [emitters]
>      emit_via = stdio
>      ```
>    - Add dual service activation supporting both `dnf-automatic.timer` and modern `dnf5-automatic.timer`.
>    - In download-only mode (`-d`), guard against modifying filesystem service configurations.
> 3. **Version Bump Alignment (`v2.0.1`)**:
>    - Bump version from `2.0` to `2.0.1` across `Linux-Deployment-Tool.sh`, `scriptsData.ts`, `repoScripts.json`, `public/raw/Linux-Deployment-Tool.sh`, `Navbar.tsx`, `SupportModal.tsx`, and `App.tsx`.

---

### 1. Overview & Root Cause Analysis

- **Defect 1: OrcaSlicer Flatpak Not Found**:
  - *Root Cause*: Flathub migrated the official application manifest from `com.softfever.OrcaSlicer` to `com.orcaslicer.OrcaSlicer`. Running `flatpak install flathub com.softfever.OrcaSlicer` returns an exit error: `error: Nothing matches com.softfever.OrcaSlicer in remote flathub`.
  - *Fix*: Update array in `Linux-Deployment-Tool.sh` to use `com.orcaslicer.OrcaSlicer` and enhance `install_flatpak_app()` with an automatic fallback mechanism.
- **Defect 2: `sed: can't read /etc/dnf/automatic.conf` Fatal Exit**:
  - *Root Cause*: Line 1139 executed `sed -i -E ... /etc/dnf/automatic.conf` immediately after `pkg_install dnf-automatic`. On minimal containers, fresh Fedora 41 installations using DNF5, or dry-run execution (`-d`), `/etc/dnf/automatic.conf` does not exist on disk. Under `set -e`, `sed` fails with exit code 2, causing premature abort of the entire deployment.
  - *Fix*: Verify file presence before calling `sed`. If absent, create `/etc/dnf` and write a pristine configuration block with `upgrade_type = security`. Add fallback activation for `dnf5-automatic.timer`.

---

### 2. Implementation Specifications

#### A. `Linux-Deployment-Tool.sh` Script Patches
1. **Header Changelog Update**:
   - Add `v2.0.1:` section under `DEFECT RESOLUTIONS & BUG FIXES`:
     - *OrcaSlicer Flathub ID*: Migrated to `com.orcaslicer.OrcaSlicer` with legacy `com.softfever.OrcaSlicer` fallback.
     - *DNF Automatic Auto-Creation*: Added automated template creation for `/etc/dnf/automatic.conf` and added support for DNF5 `dnf5-automatic.timer`.
2. **Maker Flatpak Array**:
   ```bash
   readonly MAKER_FLATPAKS=(com.orcaslicer.OrcaSlicer com.bambulab.BambuStudio)
   ```
3. **Enhanced Flatpak Installer Fallback**:
   In `install_flatpak_app()`: if `com.orcaslicer.OrcaSlicer` fails, retry with `com.softfever.OrcaSlicer` before warning.
4. **Resilient DNF Automatic Setup**:
   ```bash
   if [[ "$DISTRO_FAMILY" == "rpm" ]]; then
       if [[ -n "$DOWNLOAD_ONLY" ]]; then
           log_info "Download-only mode active: staged dnf-automatic packages."
       else
           pkg_install dnf-automatic || pkg_install dnf5-plugin-automatic || true
           local dnf_auto_conf="/etc/dnf/automatic.conf"
           mkdir -p /etc/dnf
           if [[ ! -f "$dnf_auto_conf" ]]; then
               log_info "Creating default security configuration: $dnf_auto_conf"
               cat <<'EOF' > "$dnf_auto_conf"
[commands]
upgrade_type = security
download_updates = yes
apply_updates = yes
[emitters]
emit_via = stdio
EOF
           else
               sed -i -E 's/^#?upgrade_type =.*/upgrade_type = security/' "$dnf_auto_conf" 2>/dev/null || echo "upgrade_type = security" >> "$dnf_auto_conf"
               sed -i -E 's/^#?download_updates =.*/download_updates = yes/' "$dnf_auto_conf" 2>/dev/null || echo "download_updates = yes" >> "$dnf_auto_conf"
               sed -i -E 's/^#?apply_updates =.*/apply_updates = yes/' "$dnf_auto_conf" 2>/dev/null || echo "apply_updates = yes" >> "$dnf_auto_conf"
           fi
           service_enable dnf-automatic.timer || service_enable dnf5-automatic.timer || true
       fi
   ```

#### B. Web Studio Parity & Version Bump
- Update version badge from `v2.0` to `v2.0.1` in `Navbar.tsx`, `SupportModal.tsx`, `App.tsx`, and `scriptsData.ts`.
- Update `scriptsData.ts` and `ScriptInspector.tsx` search index to reference `com.orcaslicer.OrcaSlicer` and DNF5 automatic timer hardening.
- Sync `/public/raw/Linux-Deployment-Tool.sh` and `src/data/repoScripts.json`.

---

### 3. Technical Architecture & Component Flow

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Linux-Deployment-Tool.sh                        │
├────────────────────────────────────────────────────────────────────────┤
│ 1. Flathub Package Resolver                                            │
│    Primary:   com.orcaslicer.OrcaSlicer ──► [Success]                  │
│    Fallback:  com.softfever.OrcaSlicer  ──► [Legacy Support]           │
├────────────────────────────────────────────────────────────────────────┤
│ 2. DNF Automated Patching Engine                                       │
│    Check:     /etc/dnf/automatic.conf exists?                          │
│    Yes ────►  Safely mutate with sed (upgrade_type = security)         │
│    No  ────►  Generate clean template configuration block              │
│    Timer:     Enable dnf-automatic.timer || dnf5-automatic.timer       │
└────────────────────────────────────────────────────────────────────────┘
```

---

### 4. Verification Plan

1. **Bash Syntax Integrity**:
   - Execute `bash -n Linux/Provisioning/Linux-Deployment-Tool/Linux-Deployment-Tool.sh` to guarantee zero syntax or quoting errors.
2. **Defect Verification**:
   - Verify `com.orcaslicer.OrcaSlicer` is specified in `MAKER_FLATPAKS` and `scriptsData.ts`.
   - Verify `/etc/dnf/automatic.conf` file existence check and `mkdir -p /etc/dnf` creation prevent `sed` failures.
3. **Application Build & Lint**:
   - Run `compile_applet` and `lint_applet` to confirm clean compilation across the React applet.
4. **Public Raw Sync**:
   - Confirm `/public/raw/Linux-Deployment-Tool.sh` matches the updated script content byte-for-byte.
