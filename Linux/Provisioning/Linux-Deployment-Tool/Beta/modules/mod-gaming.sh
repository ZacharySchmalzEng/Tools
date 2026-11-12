#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# ==============================================================================
# MODULE: GAMING & GPU DRIVERS (mod-gaming.sh)
# SYNOPSIS
#     Standalone & orchestrated Gaming & Driver module for Linux-Deployment-Tool.
# DESCRIPTION
#     Configures gaming repositories (RPM Fusion, Packman, Pacman multilib),
#     installs Steam, Lutris, Winetricks, GameMode, MangoHud, ProtonUp-Qt, and
#     Bottles, updates firmware via fwupdmgr, and auto-detects NVIDIA/AMD GPUs
#     via lspci + sysfs with full --reinstall and --rebuild kernel/initramfs
#     recovery support.
# CHANGELOG
#     See ../CHANGELOG.md for release history.
# ==============================================================================
set -euo pipefail

if [[ "${COMMON_LIB_LOADED:-false}" != true ]]; then
    MOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
    if [[ -f "${MOD_DIR}/../lib/common.sh" ]]; then
        COMMON_PATH="${MOD_DIR}/../lib/common.sh"
    elif [[ -f "${MOD_DIR}/lib/common.sh" ]]; then
        COMMON_PATH="${MOD_DIR}/lib/common.sh"
    else
        COMMON_PATH="${MOD_DIR}/../lib/common.sh"
        mkdir -p "$(dirname "$COMMON_PATH")"
        REPO_BASE="${LDT_REPO_BASE_URL:-https://raw.githubusercontent.com/ZacharySchmalzEng/Tools/main/Linux/Provisioning/Linux-Deployment-Tool/Beta}"
        echo -e "\e[36m[INFO] Shared library not found locally. Downloading lib/common.sh from GitHub...\e[0m"
        if command -v curl &>/dev/null; then
            curl --connect-timeout 10 --max-time 60 --retry 3 -fsSL "${REPO_BASE}/lib/common.sh" -o "$COMMON_PATH"
        elif command -v wget &>/dev/null; then
            wget -q --timeout=60 --tries=3 -O "$COMMON_PATH" "${REPO_BASE}/lib/common.sh"
        else
            echo -e "\e[31m[ERROR] Neither curl nor wget is available to download lib/common.sh.\e[0m" >&2
            exit 1
        fi
        chmod 0700 "$COMMON_PATH"
    fi
    # shellcheck disable=SC1090
    source "$COMMON_PATH"
fi

init_standalone_module "mod-gaming.sh" "$@"

echo -e "\n\e[35m[========== STARTING GAMING & DRIVER MODULE ==========]\e[0m"
if [[ "$DISTRO_FAMILY" == "rpm" ]]; then
    PRE_PKGS=(flatpak snap dnf-plugins-core)
    pkg_install "${PRE_PKGS[@]}"
    if [[ "$IS_NOBARA" != true ]]; then
        fedora_ver=$(rpm -E %fedora 2>/dev/null || true)
        if [[ -z "$fedora_ver" || "$fedora_ver" == "%fedora" ]]; then
            fedora_ver="${VERSION_ID:-41}"
            fedora_ver="${fedora_ver%%.*}"
        fi
        pkg_install "https://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-${fedora_ver}.noarch.rpm" || true
        pkg_install "https://download1.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-${fedora_ver}.noarch.rpm" || true
        CACHE_REFRESHED=false
        dnf "${DNF_RETRY_OPTIONS[@]}" group upgrade core ${AUTO_YES:+$AUTO_YES} || true
    else
        log_info "Nobara detected: Native gaming repository stack & Wine dependencies already active."
    fi
elif [[ "$DISTRO_FAMILY" == "opensuse" ]]; then
    log_info "openSUSE detected: Adding Packman Essentials repository for gaming & multimedia codecs..."
    zypper ar -cfp 90 https://ftp.gwdg.de/pub/linux/misc/packman/suse/openSUSE_Tumbleweed/Essentials/ packman-essentials 2>/dev/null || \
    zypper ar -cfp 90 "https://ftp.gwdg.de/pub/linux/misc/packman/suse/openSUSE_Leap_\$releasever/Essentials/" packman-essentials 2>/dev/null || true
elif [[ "$DISTRO_FAMILY" == "arch" || "$DISTRO_FAMILY" == "steamos" ]]; then
    log_info "Verifying multilib repository is active in /etc/pacman.conf..."
    enable_multilib_repository
else
    pkg_install flatpak snapd
fi

ensure_flatpak
GAMING_PKGS=(winetricks steam lutris gamemode mangohud)
pkg_install "${GAMING_PKGS[@]}"
install_flatpak_app net.davidotek.pupgui2 || true
install_flatpak_app com.usebottles.bottles || true

if command -v fwupdmgr &>/dev/null; then
    fwupdmgr refresh --force || true
    fwupdmgr get-devices || true
    fwupdmgr update ${AUTO_YES:+$AUTO_YES} || true
fi

GPU_INFO=""
if command -v lspci &>/dev/null; then
    GPU_INFO=$(lspci -nn 2>/dev/null | grep -E 'VGA|3D controller|Display controller' || true)
fi
# Use sysfs if lspci did not identify a supported discrete GPU vendor.
if ! grep -qiE 'NVIDIA|Advanced Micro Devices|AMD' <<< "$GPU_INFO" && [[ -d /sys/bus/pci/devices ]]; then
    if grep -qsi "0x10de" /sys/bus/pci/devices/*/vendor 2>/dev/null; then
        GPU_INFO="NVIDIA Corporation [PCI ID 0x10de auto-detected via sysfs]"
    elif grep -qsi "0x1002" /sys/bus/pci/devices/*/vendor 2>/dev/null; then
        GPU_INFO="Advanced Micro Devices, Inc. [AMD/ATI PCI ID 0x1002 auto-detected via sysfs]"
    fi
fi

case "$GPU_INFO" in
    *"NVIDIA"*)
        if [[ "$IS_NOBARA" == true ]]; then
            if [[ "$RUN_REBUILD" == true ]]; then
                log_warn "Nobara Linux + Rebuild: Re-installing Nobara NVIDIA DKMS driver stack and rebuilding kernel modules..."
                dnf "${DNF_RETRY_OPTIONS[@]}" reinstall ${AUTO_YES:+$AUTO_YES} "*nvidia*" || log_warn "Nobara NVIDIA package reinstall returned warnings."
                if command -v dkms &>/dev/null; then
                    run_cmd "Rebuilding DKMS kernel modules" dkms autoinstall || true
                fi
                if command -v dracut &>/dev/null; then
                    run_cmd "Regenerating initramfs image via dracut" dracut --force || true
                fi
            else
                log_success "Nobara Linux detected: NVIDIA proprietary drivers are pre-installed via DKMS & the official 'nobara-nvidia-production' repository."
                log_info "Nobara Best Practice: Skipping manual akmod-nvidia installation to prevent fatal transaction conflicts. Use '--rebuild' with '--gaming' if you need to force-repair corrupted Nobara NVIDIA drivers."
            fi
        elif [[ "$IS_BAZZITE" == true ]]; then
            if [[ "$RUN_REINSTALL" == true ]]; then
                log_warn "Bazzite manages NVIDIA drivers in its host image; --reinstall/--rebuild cannot reinstall or rebuild the host driver stack."
            else
                log_success "Bazzite detected: Bazzite ships with pre-configured NVIDIA container images. Host driver layering is intentionally skipped."
            fi
        elif [[ "$IS_STEAMOS" == true ]]; then
            log_info "SteamOS detected: Valve Linux kernel exclusively targets AMD APU hardware (Steam Deck). Skipping NVIDIA desktop drivers."
        elif [[ "$IS_ATOMIC" == true ]]; then
            log_info "Fedora Atomic (Silverblue/Kinoite) detected. Layering akmod-nvidia via rpm-ostree..."
            if [[ "$RUN_REBUILD" == true ]]; then
                log_warn "--rebuild will discard the pending rpm-ostree deployment, including unrelated staged changes, before layering the NVIDIA driver packages."
                if ! run_cmd "Cleaning pending rpm-ostree deployment" rpm-ostree cleanup --pending; then
                    log_warn "Could not clean the pending rpm-ostree deployment; continuing with normal idempotent layering."
                fi
                log_warn "rpm-ostree cannot force-reinstall layered NVIDIA drivers; rebuilding uses normal idempotent layering after pending cleanup."
            elif [[ "$RUN_REINSTALL" == true ]]; then
                log_warn "rpm-ostree cannot force-reinstall layered NVIDIA drivers; --reinstall will only apply normal idempotent layering."
            fi
            rpm-ostree install --idempotent akmod-nvidia xorg-x11-drv-nvidia nvidia-settings vulkan-tools || log_warn "rpm-ostree driver layering failed or requires a scheduled reboot."
        elif [[ "$DISTRO_FAMILY" == "arch" ]]; then
            log_info "Arch Linux detected: Installing nvidia-dkms and utilities via pacman..."
            if [[ "$RUN_REBUILD" == true ]]; then
                arch_nvidia_cmd=(pacman -S --overwrite '*')
                if [[ "$AUTO_YES" == "-y" ]]; then arch_nvidia_cmd+=(--noconfirm); fi
                arch_nvidia_cmd+=(nvidia-dkms nvidia-utils lib32-nvidia-utils nvidia-settings vulkan-tools)
                refresh_package_cache
                if ! run_cmd "Reinstalling Arch NVIDIA driver packages with file overwrite enabled" "${arch_nvidia_cmd[@]}"; then
                    log_warn "DKMS driver package transaction failed; trying the prebuilt NVIDIA driver stack."
                    arch_nvidia_fallback_cmd=(pacman -S --overwrite '*')
                    if [[ "$AUTO_YES" == "-y" ]]; then arch_nvidia_fallback_cmd+=(--noconfirm); fi
                    arch_nvidia_fallback_cmd+=(nvidia nvidia-utils nvidia-settings vulkan-tools)
                    run_cmd "Reinstalling prebuilt Arch NVIDIA driver packages with file overwrite enabled" "${arch_nvidia_fallback_cmd[@]}" || log_warn "Prebuilt NVIDIA driver package transaction failed."
                fi
            else
                pkg_install nvidia-dkms nvidia-utils lib32-nvidia-utils nvidia-settings vulkan-tools || pkg_install nvidia nvidia-utils nvidia-settings vulkan-tools || true
            fi
            if [[ "$RUN_REBUILD" == true ]] && command -v mkinitcpio &>/dev/null; then
                run_cmd "Regenerating Arch Linux initramfs (mkinitcpio -P)" mkinitcpio -P || true
            fi
        elif [[ "$DISTRO_FAMILY" == "opensuse" ]]; then
            log_info "openSUSE detected: Adding official openSUSE NVIDIA repository..."
            zypper addrepo --refresh https://download.nvidia.com/opensuse/tumbleweed NVIDIA 2>/dev/null || zypper addrepo --refresh https://download.nvidia.com/opensuse/leap/\$releasever NVIDIA 2>/dev/null || true
            pkg_install x11-video-nvidiaG06 nvidia-glG06 nvidia-computeG06 vulkan-tools || true
            if [[ "$RUN_REBUILD" == true ]] && command -v dracut &>/dev/null; then
                run_cmd "Regenerating openSUSE initramfs via dracut" dracut --force || true
            fi
        elif [[ "$DISTRO_FAMILY" == "deb" ]]; then
            if command -v ubuntu-drivers &>/dev/null; then
                if [[ "$RUN_REINSTALL" == true ]]; then
                    ubuntu_nvidia_packages=()
                    mapfile -t ubuntu_nvidia_packages < <(
                        dpkg-query -W -f='${db:Status-Abbrev} ${binary:Package}\n' \
                            'nvidia-driver-*' 'nvidia-dkms-*' 'nvidia-kernel-*' \
                            'nvidia-firmware-*' 'nvidia-utils-*' 'libnvidia-gl-*' \
                            'libnvidia-compute-*' 'libnvidia-extra-*' 'libnvidia-decode-*' \
                            'libnvidia-encode-*' 'libnvidia-cfg1-*' 'libnvidia-fbc1-*' \
                            2>/dev/null | awk '$1 == "ii" { print $2 }'
                    )
                    if [[ ${#ubuntu_nvidia_packages[@]} -gt 0 ]]; then
                        if ! pkg_install "${ubuntu_nvidia_packages[@]}"; then
                            log_warn "Ubuntu NVIDIA package reinstallation failed."
                        fi
                    else
                        log_warn "No installed Ubuntu NVIDIA driver packages found; using ubuntu-drivers to install the recommended driver."
                        if ! ubuntu-drivers autoinstall; then
                            log_warn "ubuntu-drivers could not install the recommended NVIDIA driver."
                        fi
                    fi
                elif ! ubuntu-drivers autoinstall; then
                    log_warn "ubuntu-drivers could not install the recommended NVIDIA driver."
                fi
            else
                if ! pkg_install nvidia-driver firmware-misc-nonfree nvidia-settings vulkan-tools; then
                    log_warn "Debian NVIDIA package installation or reinstallation failed."
                fi
            fi
            if [[ "$RUN_REBUILD" == true ]]; then
                if command -v dkms &>/dev/null; then
                    run_cmd "Rebuilding installed DKMS modules" dkms autoinstall || log_warn "DKMS module rebuild reported warnings."
                fi
                if command -v update-initramfs &>/dev/null; then
                    run_cmd "Regenerating initramfs for installed kernels" update-initramfs -u -k all || log_warn "Initramfs regeneration reported warnings."
                fi
            fi
        else
            pkg_install akmod-nvidia xorg-x11-drv-nvidia nvidia-settings vulkan-tools || true
            if [[ "$RUN_REBUILD" == true ]]; then
                if command -v akmods &>/dev/null; then
                    run_cmd "Forcing akmods kernel module rebuild" akmods --force || true
                fi
                if command -v dracut &>/dev/null; then
                    run_cmd "Regenerating initramfs via dracut" dracut --force || true
                fi
            fi
        fi
        ;;
    *"AMD"*|*"Advanced Micro Devices"*)
        log_info "AMD GPU detected. Installing Mesa/Vulkan driver stack..."
        case "$DISTRO_FAMILY" in
            atomic)
                log_info "Fedora Atomic/Bazzite includes Mesa/RADV drivers in base image."
                ;;
            steamos)
                if [[ "$RUN_REBUILD" == true ]]; then
                    refresh_package_cache
                    steamos_unlock
                    steamos_gpu_cmd=(pacman -S --overwrite '*')
                    if [[ "$AUTO_YES" == "-y" ]]; then steamos_gpu_cmd+=(--noconfirm); fi
                    steamos_gpu_cmd+=(mesa lib32-mesa vulkan-radeon lib32-vulkan-radeon vulkan-tools)
                    if ! run_cmd "Reinstalling SteamOS AMD graphics packages with file overwrite enabled" "${steamos_gpu_cmd[@]}"; then
                        log_warn "SteamOS AMD graphics package transaction failed."
                    fi
                    steamos_lock
                else
                    log_info "SteamOS native AMD Mesa/RADV driver stack is active."
                fi
                ;;
            arch)
                if [[ "$RUN_REBUILD" == true ]]; then
                    arch_amd_cmd=(pacman -S --overwrite '*')
                    if [[ "$AUTO_YES" == "-y" ]]; then arch_amd_cmd+=(--noconfirm); fi
                    arch_amd_cmd+=(mesa lib32-mesa vulkan-radeon lib32-vulkan-radeon vulkan-tools)
                    refresh_package_cache
                    run_cmd "Reinstalling Arch AMD graphics packages with file overwrite enabled" "${arch_amd_cmd[@]}" || log_warn "Arch AMD graphics package transaction failed."
                else
                    pkg_install mesa lib32-mesa vulkan-radeon lib32-vulkan-radeon vulkan-tools || true
                fi
                ;;
            opensuse)
                pkg_install Mesa Mesa-libva libvulkan_radeon vulkan-tools || true
                ;;
            deb)
                pkg_install mesa-vulkan-drivers vulkan-tools libvulkan1 || true
                ;;
            *)
                pkg_install mesa-vulkan-drivers vulkan-tools vulkan-loader || true
                ;;
        esac
        if [[ "$RUN_REBUILD" == true ]] && command -v dracut &>/dev/null && [[ "$IS_ATOMIC" != true ]]; then
            run_cmd "Regenerating initramfs for AMD Mesa/amdgpu stack" dracut --force || true
        fi
        ;;
    *)
        log_warn "Unable to detect a supported NVIDIA or AMD GPU. Skipping driver installation."
        ;;
esac

log_success "Gaming module complete."
