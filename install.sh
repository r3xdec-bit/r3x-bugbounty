#!/usr/bin/env bash
# ==============================================================================
# R3X-BugBounty — Automated Environment & Tool Installer
# Supports: Kali Linux, Debian, Ubuntu, Arch Linux
# ==============================================================================

set -o pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

LOG_FILE="install.log"
INSTALL_PREFIX="${HOME}/.local/bin"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${PROJECT_DIR}/bin"

mkdir -p "${BIN_DIR}" "${INSTALL_PREFIX}"
echo "=== R3X-BugBounty Installation Log - $(date) ===" > "${LOG_FILE}"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "${LOG_FILE}"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1" | tee -a "${LOG_FILE}"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1" | tee -a "${LOG_FILE}"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "${LOG_FILE}"
}

banner() {
    echo -e "${CYAN}${BOLD}"
    cat << "EOF"
  ██████╗ ██████╗ ██╗  ██╗       ██████╗ ██╗   ██╗ ██████╗ 
  ██╔══██╗╚════██╗╚██╗██╔╝       ██╔══██╗██║   ██║██╔════╝ 
  ██████╔╝ █████╔╝ ╚███╔╝  █████╗██████╔╝██║   ██║██║  ███╗
  ██╔══██╗ ╚═══██╗ ██╔██╗  ╚════╝██╔══██╗██║   ██║██║   ██║
  ██║  ██║██████╔╝██╔╝ ██╗       ██████╔╝╚██████╔╝╚██████╔╝
  ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝       ╚═════╝  ╚═════╝  ╚═════╝ 
        Autonomous AI Security & Bug Bounty Framework
EOF
    echo -e "${NC}"
}

banner

# ------------------------------------------------------------------------------
# 1. Distribution Detection
# ------------------------------------------------------------------------------
log_info "Detecting Linux Distribution..."

DISTRO="unknown"
PKG_MGR="unknown"

if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "${ID}" in
        kali)
            DISTRO="Kali Linux"
            PKG_MGR="apt"
            ;;
        debian|ubuntu|linuxmint|pop)
            DISTRO="${NAME:-Debian-based}"
            PKG_MGR="apt"
            ;;
        arch|manjaro|endeavouros)
            DISTRO="${NAME:-Arch-based}"
            PKG_MGR="pacman"
            ;;
        *)
            if [ -n "${ID_LIKE}" ]; then
                case "${ID_LIKE}" in
                    *debian*) DISTRO="Debian-based (${ID})"; PKG_MGR="apt" ;;
                    *arch*) DISTRO="Arch-based (${ID})"; PKG_MGR="pacman" ;;
                    *) DISTRO="${ID}"; PKG_MGR="unknown" ;;
                esac
            fi
            ;;
    esac
fi

log_success "Operating System: ${DISTRO}"
log_info "Detected Package Manager: ${PKG_MGR}"

# ------------------------------------------------------------------------------
# 2. Check Security Tools Status
# ------------------------------------------------------------------------------
log_info "Scanning for required security tools..."

REQUIRED_TOOLS=("nmap" "whatweb" "nuclei" "httpx" "subfinder" "katana" "amass" "sslyze" "dnsx")
MISSING_TOOLS=()
FOUND_TOOLS=()

check_httpx_binary() {
    # Ensure httpx is ProjectDiscovery httpx, not Python httpx
    local p
    p=$(command -v httpx 2>/dev/null)
    if [ -n "$p" ]; then
        if "$p" -version 2>&1 | grep -iq "projectdiscovery"; then
            return 0
        fi
    fi
    if [ -x "${BIN_DIR}/httpx" ]; then
        if "${BIN_DIR}/httpx" -version 2>&1 | grep -iq "projectdiscovery"; then
            return 0
        fi
    fi
    return 1
}

for tool in "${REQUIRED_TOOLS[@]}"; do
    if [ "$tool" == "httpx" ]; then
        if check_httpx_binary; then
            FOUND_TOOLS+=("$tool (ProjectDiscovery)")
        else
            MISSING_TOOLS+=("$tool")
        fi
    elif command -v "$tool" &>/dev/null || [ -x "${BIN_DIR}/$tool" ] || [ -x "${INSTALL_PREFIX}/$tool" ]; then
        FOUND_TOOLS+=("$tool")
    else
        MISSING_TOOLS+=("$tool")
    fi
done

echo ""
echo -e "${BOLD}--- Security Tools Status ---${NC}"
for t in "${FOUND_TOOLS[@]}"; do
    echo -e "  [${GREEN}FOUND${NC}]     $t"
done
for t in "${MISSING_TOOLS[@]}"; do
    echo -e "  [${RED}MISSING${NC}]   $t"
done
echo ""

# ------------------------------------------------------------------------------
# 3. User Consent & Confirmation
# ------------------------------------------------------------------------------
if [ ${#MISSING_TOOLS[@]} -eq 0 ]; then
    log_success "All required security tools are present!"
else
    echo -e "${YELLOW}${BOLD}The following tools need to be installed:${NC}"
    echo -e "  ${MISSING_TOOLS[*]}"
    echo ""
    read -r -p "Do you want to proceed with installing missing tools and configuring Python venv? [y/N]: " consent
    if [[ ! "$consent" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        log_warn "Installation cancelled by user."
        exit 0
    fi
fi

# ------------------------------------------------------------------------------
# 4. System Package Installation (Optional Sudo)
# ------------------------------------------------------------------------------
install_system_pkgs() {
    local pkgs=("$@")
    if [ ${#pkgs[@]} -eq 0 ]; then
        return 0
    fi

    log_info "Attempting to install system packages: ${pkgs[*]}"
    if [ "$(id -u)" -eq 0 ]; then
        if [ "$PKG_MGR" == "apt" ]; then
            apt update -qq && apt install -y -qq "${pkgs[@]}" >> "${LOG_FILE}" 2>&1
        elif [ "$PKG_MGR" == "pacman" ]; then
            pacman -Sy --noconfirm "${pkgs[@]}" >> "${LOG_FILE}" 2>&1
        fi
    elif command -v sudo &>/dev/null; then
        echo -e "${CYAN}[sudo] Installing system packages via ${PKG_MGR}...${NC}"
        if [ "$PKG_MGR" == "apt" ]; then
            sudo apt update -qq && sudo apt install -y -qq "${pkgs[@]}" >> "${LOG_FILE}" 2>&1
        elif [ "$PKG_MGR" == "pacman" ]; then
            sudo pacman -Sy --noconfirm "${pkgs[@]}" >> "${LOG_FILE}" 2>&1
        fi
    else
        log_warn "Neither root nor sudo available. Skipping system packages."
        return 1
    fi
}

SYS_DEPS=()
if ! command -v git &>/dev/null; then SYS_DEPS+=("git"); fi
if ! command -v curl &>/dev/null; then SYS_DEPS+=("curl"); fi
if ! command -v tar &>/dev/null; then SYS_DEPS+=("tar"); fi
if ! command -v unzip &>/dev/null; then SYS_DEPS+=("unzip"); fi

# Nmap via package manager if missing
if [[ " ${MISSING_TOOLS[*]} " =~ " nmap " ]]; then
    SYS_DEPS+=("nmap")
fi

# Whatweb via package manager if available
if [[ " ${MISSING_TOOLS[*]} " =~ " whatweb " ]]; then
    if [ "$PKG_MGR" == "apt" ]; then
        SYS_DEPS+=("whatweb")
    elif [ "$PKG_MGR" == "pacman" ]; then
        # On Arch whatweb is in AUR, so pacman won't have it directly
        :
    fi
fi

if [ ${#SYS_DEPS[@]} -gt 0 ]; then
    install_system_pkgs "${SYS_DEPS[@]}"
fi

# ------------------------------------------------------------------------------
# 5. Download Official Binaries (ProjectDiscovery, OWASP, etc.)
# ------------------------------------------------------------------------------
download_github_release() {
    local repo="$1"
    local pattern="$2"
    local bin_name="$3"
    local target_path="${BIN_DIR}/${bin_name}"

    log_info "Downloading ${bin_name} from ${repo}..."
    local download_url
    download_url=$(curl -s "https://api.github.com/repos/${repo}/releases/latest" \
        | grep "browser_download_url" \
        | grep -i "${pattern}" \
        | head -n 1 \
        | cut -d '"' -f 4)

    if [ -z "$download_url" ]; then
        log_error "Failed to find release asset for ${bin_name} (${repo}). Check network or API limits."
        return 1
    fi

    local temp_archive="/tmp/${bin_name}_archive"
    if curl -sSL -o "${temp_archive}" "${download_url}"; then
        local extract_dir="/tmp/${bin_name}_extract"
        mkdir -p "${extract_dir}"
        if [[ "$download_url" =~ \.zip$ ]]; then
            unzip -q -o "${temp_archive}" -d "${extract_dir}" 2>/dev/null
        else
            tar -xzf "${temp_archive}" -C "${extract_dir}" 2>/dev/null
        fi

        local found_bin
        found_bin=$(find "${extract_dir}" -type f -name "${bin_name}" | head -n 1)
        if [ -n "$found_bin" ]; then
            cp "${found_bin}" "${target_path}"
            chmod +x "${target_path}"
            ln -sf "${target_path}" "${INSTALL_PREFIX}/${bin_name}" 2>/dev/null || true
            log_success "Successfully installed ${bin_name} to ${target_path}"
            rm -rf "${temp_archive}" "${extract_dir}"
            return 0
        else
            log_error "Could not find binary ${bin_name} in extracted archive."
        fi
        rm -rf "${temp_archive}" "${extract_dir}"
    else
        log_error "Download failed for ${download_url}"
    fi
    return 1
}

# Install missing Go / Security binaries
for tool in "${MISSING_TOOLS[@]}"; do
    case "$tool" in
        nuclei)
            download_github_release "projectdiscovery/nuclei" "linux_amd64.zip" "nuclei"
            ;;
        httpx)
            download_github_release "projectdiscovery/httpx" "linux_amd64.zip" "httpx"
            ;;
        subfinder)
            download_github_release "projectdiscovery/subfinder" "linux_amd64.zip" "subfinder"
            ;;
        katana)
            download_github_release "projectdiscovery/katana" "linux_amd64.zip" "katana"
            ;;
        dnsx)
            download_github_release "projectdiscovery/dnsx" "linux_amd64.zip" "dnsx"
            ;;
        amass)
            download_github_release "owasp-amass/amass" "linux_amd64.zip" "amass" || \
            download_github_release "owasp-amass/amass" "linux_amd64.tar.gz" "amass"
            ;;
        sslyze)
            log_info "SSLyze will be installed via Python Virtualenv."
            ;;
        whatweb)
            if [ ! -x "${BIN_DIR}/whatweb" ]; then
                log_info "Cloning WhatWeb repository into bin/whatweb..."
                git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git "${BIN_DIR}/WhatWeb_repo" >> "${LOG_FILE}" 2>&1
                if [ -f "${BIN_DIR}/WhatWeb_repo/whatweb" ]; then
                    ln -sf "${BIN_DIR}/WhatWeb_repo/whatweb" "${BIN_DIR}/whatweb"
                    ln -sf "${BIN_DIR}/whatweb" "${INSTALL_PREFIX}/whatweb" 2>/dev/null || true
                    log_success "WhatWeb installed via repository link."
                fi
            fi
            ;;
    esac
done

# ------------------------------------------------------------------------------
# 6. Setup Python Virtual Environment (.venv)
# ------------------------------------------------------------------------------
log_info "Configuring Python 3 Virtual Environment..."

VENV_DIR="${PROJECT_DIR}/.venv"
if [ ! -d "${VENV_DIR}" ]; then
    python3 -m venv "${VENV_DIR}" >> "${LOG_FILE}" 2>&1
    if [ $? -ne 0 ]; then
        log_error "Failed to create python virtual environment."
        exit 1
    fi
    log_success "Virtual environment created at ${VENV_DIR}"
else
    log_info "Existing virtual environment found."
fi

# Activate and install python requirements
"${VENV_DIR}/bin/pip" install --upgrade pip >> "${LOG_FILE}" 2>&1
if [ -f "${PROJECT_DIR}/requirements.txt" ]; then
    log_info "Installing Python dependencies from requirements.txt..."
    "${VENV_DIR}/bin/pip" install -r "${PROJECT_DIR}/requirements.txt" >> "${LOG_FILE}" 2>&1
    if [ $? -eq 0 ]; then
        log_success "Python dependencies installed successfully."
    else
        log_error "Error installing some Python dependencies. Check ${LOG_FILE}"
    fi
fi

# Also install sslyze into venv if requested
if [[ " ${MISSING_TOOLS[*]} " =~ " sslyze " ]]; then
    log_info "Installing SSLyze into venv..."
    "${VENV_DIR}/bin/pip" install sslyze >> "${LOG_FILE}" 2>&1
    if [ -f "${VENV_DIR}/bin/sslyze" ]; then
        ln -sf "${VENV_DIR}/bin/sslyze" "${BIN_DIR}/sslyze"
        ln -sf "${BIN_DIR}/sslyze" "${INSTALL_PREFIX}/sslyze" 2>/dev/null || true
        log_success "SSLyze installed in virtual environment."
    fi
fi

# Install R3X package in editable mode
"${VENV_DIR}/bin/pip" install -e "${PROJECT_DIR}" >> "${LOG_FILE}" 2>&1
if [ -f "${VENV_DIR}/bin/r3x" ]; then
    ln -sf "${VENV_DIR}/bin/r3x" "${INSTALL_PREFIX}/r3x" 2>/dev/null || true
    ln -sf "${VENV_DIR}/bin/r3x" "${BIN_DIR}/r3x" 2>/dev/null || true
    log_success "Installed 'r3x' CLI entry point."
fi

# ------------------------------------------------------------------------------
# 7. Final Verification & Status Report
# ------------------------------------------------------------------------------
echo ""
echo -e "${BOLD}--- Verification Audit ---${NC}"
ALL_OK=true

export PATH="${BIN_DIR}:${INSTALL_PREFIX}:${VENV_DIR}/bin:${PATH}"

for tool in "${REQUIRED_TOOLS[@]}"; do
    if [ "$tool" == "httpx" ]; then
        if check_httpx_binary; then
            echo -e "  [${GREEN}VERIFIED${NC}] $tool (ProjectDiscovery)"
        else
            echo -e "  [${RED}FAILED${NC}]   $tool (Not verified or wrong binary)"
            ALL_OK=false
        fi
    elif command -v "$tool" &>/dev/null; then
        ver=$(command "$tool" --version 2>/dev/null || command "$tool" -version 2>/dev/null | head -n 1 || echo "installed")
        echo -e "  [${GREEN}VERIFIED${NC}] $tool: ${ver:0:40}"
    else
        echo -e "  [${YELLOW}OPTIONAL/FAILED${NC}] $tool: Not in PATH"
        ALL_OK=false
    fi
done

echo ""
if [ "$ALL_OK" = true ]; then
    log_success "Environment configuration completed successfully!"
else
    log_warn "Some tools could not be installed automatically. Refer to ${LOG_FILE} and INSTALLATION.md."
fi

echo -e "${CYAN}To activate the R3X environment:${NC}"
echo -e "  source ${VENV_DIR}/bin/activate"
echo -e "  export PATH=\"${BIN_DIR}:\${PATH}\""
echo -e "  r3x --help"
