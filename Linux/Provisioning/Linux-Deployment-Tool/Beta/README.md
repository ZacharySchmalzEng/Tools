# Linux Deployment Tool — v3.0 Beta (`./Beta` Modular Suite)

Automated, multi-distribution Linux provisioning, gaming setup, and CIS/SecOps hardening suite. Version `3.0-beta` (branch `beta/modular-v3`) places the main modular runner (`Linux-Deployment-Tool.sh`) at the **top of the `./Beta` directory**, alongside `CHANGELOG.md`, `README.md`, `lib/common.sh`, and `modules/mod-*.sh`.

For full release notes, security mitigations, bug fixes, and feature enhancements, see **[CHANGELOG.md](./CHANGELOG.md)**.

---

## `./Beta` Directory Layout (Top-Level Runner + Modular Child Scripts)

The main orchestrator (`Linux-Deployment-Tool.sh`) sits at the top of `./Beta` so the `./Beta` directory can be downloaded and extracted as a simple tarball (`Linux-Deployment-Tool-Beta.tar.gz`) or executed as a standalone script that fetches only requested modules on demand into `./lib/` and `./modules/`:

```text
Beta/
├── Linux-Deployment-Tool.sh       # Main runner at the top of ./Beta
├── CHANGELOG.md                   # Separated security, defect, and feature release history
├── README.md                      # Modular architecture & usage documentation
├── Linux-Deployment-Tool-Beta.tar.gz # Pre-packaged downloadable tarball of ./Beta
├── lib/
│   └── common.sh                  # Shared core library (distro routing, logging, traps, helpers)
└── modules/
    ├── mod-update.sh              # --update          (System, Flatpak, Snap upgrades + distro-sync)
    ├── mod-apps.sh                # --apps            (Core QoL CLI/GUI utilities + DE tools)
    ├── mod-devapps.sh             # --devapps         (Git, jq, fzf, tealdeer, rsync, pwsh, VS Code)
    ├── mod-sysadmin.sh            # --sysadmin        (Remmina, tmux, network/disk/process tools)
    ├── mod-cyber.sh               # --cyber           (Wireshark, Nmap, TCPDump, Ncat)
    ├── mod-maker.sh               # --maker           (PrusaSlicer, OrcaSlicer, BambuStudio)
    ├── mod-creators.sh            # --creators        (GIMP, Krita, Blender, Audacity, Inkscape, OBS)
    ├── mod-harden.sh              # --harden          (SELinux/AppArmor, auto-updates, CIS SSH)
    ├── mod-harden-adv.sh          # --harden-advanced (CIS L2 sysctl, auditd rules, no password SSH)
    ├── mod-ssh.sh                 # --ssh [--2fa]     (OpenSSH Server + optional Google Auth PAM MFA)
    ├── mod-discord.sh             # --discord         (Native RPM on Fedora/Nobara, Flatpak on Atomic)
    └── mod-gaming.sh              # --gaming          (Steam, Lutris, GameMode, GPU Drivers + rebuild)
```

---

## Three Ways to Run

### 1. Simple Tarball Download (Full `./Beta` Directory)
Download and extract `Linux-Deployment-Tool-Beta.tar.gz` — the main runner `Linux-Deployment-Tool.sh` is located directly at the top of the extracted directory:

```bash
curl -fsSL https://raw.githubusercontent.com/ZacharySchmalzEng/Tools/beta/modular-v3/Linux/Provisioning/Linux-Deployment-Tool/Beta/Linux-Deployment-Tool-Beta.tar.gz | tar -xz
sudo ./Linux-Deployment-Tool.sh --update --apps --gaming -y
```

### 2. Lightweight Main Runner (On-Demand GitHub Module Fetching)
Download **only** `Beta/Linux-Deployment-Tool.sh`. When executed, it automatically downloads `lib/common.sh` and **only the child module scripts matching the flags you pass**, caching them locally in `./lib/` and `./modules/` for future runs:

```bash
curl -fsSL https://raw.githubusercontent.com/ZacharySchmalzEng/Tools/beta/modular-v3/Linux/Provisioning/Linux-Deployment-Tool/Beta/Linux-Deployment-Tool.sh -o Linux-Deployment-Tool.sh
chmod +x Linux-Deployment-Tool.sh
sudo ./Linux-Deployment-Tool.sh --devapps --sysadmin -y
```

### 3. Standalone Child Script Execution
Every child module in `modules/mod-*.sh` can be executed directly on its own without the main orchestrator. If `lib/common.sh` is not present locally, the child script automatically fetches it from GitHub before running:

```bash
sudo ./modules/mod-gaming.sh --rebuild -y
sudo ./modules/mod-ssh.sh --2fa -y
```
