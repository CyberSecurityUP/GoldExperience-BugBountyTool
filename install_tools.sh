#!/bin/bash

# ============================================================================
# ReconTool - Automated Tool Installer
# ============================================================================
# This script automatically installs all reconnaissance tools required by
# ReconTool. Supports Linux (Debian/Ubuntu, Arch, Fedora) and macOS.
#
# Usage:
#   chmod +x install_tools.sh
#   sudo ./install_tools.sh
#
# Options:
#   --no-go       Skip Go-based tools
#   --no-python   Skip Python-based tools
#   --no-system   Skip system packages
#   --dry-run     Show what would be installed without installing
#   --help        Show this help message
# ============================================================================

# DO NOT use set -e - we want to continue on errors

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Configuration
GO_BIN_PATH="/usr/local/bin"
INSTALL_DIR="/opt/recon-tools"
LOG_FILE="/tmp/recontool_install.log"

# Flags
SKIP_GO=false
SKIP_PYTHON=false
SKIP_SYSTEM=false
DRY_RUN=false

# Counters
INSTALLED=0
SKIPPED=0
FAILED=0

# ============================================================================
# Helper Functions
# ============================================================================

log() {
    echo -e "${GREEN}[+]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1" >> "$LOG_FILE"
}

error() {
    echo -e "${RED}[-]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" >> "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[*]${NC} $1"
}

banner() {
    echo -e "${CYAN}"
    echo "============================================================"
    echo "  $1"
    echo "============================================================"
    echo -e "${NC}"
}

check_root() {
    # On macOS, we don't need root for most things (Homebrew doesn't like root)
    if [[ "$OS" == "macos" ]]; then
        if [[ $EUID -eq 0 ]]; then
            warn "On macOS, running as root can cause issues with Homebrew"
            warn "Some operations may require your password"
        fi
        return 0
    fi

    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use sudo)"
        error "On macOS, run without sudo: ./install_tools.sh"
        exit 1
    fi
}

detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        PACKAGE_MANAGER="brew"
    elif [[ -f /etc/debian_version ]]; then
        OS="debian"
        PACKAGE_MANAGER="apt"
    elif [[ -f /etc/arch-release ]]; then
        OS="arch"
        PACKAGE_MANAGER="pacman"
    elif [[ -f /etc/fedora-release ]]; then
        OS="fedora"
        PACKAGE_MANAGER="dnf"
    elif [[ -f /etc/redhat-release ]]; then
        OS="rhel"
        PACKAGE_MANAGER="yum"
    else
        OS="unknown"
        PACKAGE_MANAGER="unknown"
    fi

    log "Detected OS: $OS (Package Manager: $PACKAGE_MANAGER)"
}

detect_arch() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        *)
            warn "Unknown architecture: $ARCH"
            ;;
    esac
    log "Detected Architecture: $ARCH"
}

command_exists() {
    command -v "$1" &> /dev/null
}

# Safe download function with validation
safe_download() {
    local url=$1
    local output=$2
    local min_size=${3:-1000}  # Minimum file size in bytes (default 1KB)

    curl -sLo "$output" "$url"

    # Check if file exists and has content
    if [[ ! -f "$output" ]]; then
        return 1
    fi

    # Check file size
    local size=$(wc -c < "$output" 2>/dev/null || echo 0)
    if [[ $size -lt $min_size ]]; then
        rm -f "$output"
        return 1
    fi

    return 0
}

install_if_missing() {
    local cmd=$1
    local install_func=$2

    if command_exists "$cmd"; then
        info "$cmd is already installed"
        ((SKIPPED++))
        return 0
    fi

    if $DRY_RUN; then
        info "[DRY RUN] Would install: $cmd"
        return 0
    fi

    log "Installing $cmd..."

    # Run the install function and capture result
    if $install_func 2>> "$LOG_FILE"; then
        if command_exists "$cmd"; then
            log "$cmd installed successfully"
            ((INSTALLED++))
            return 0
        fi
    fi

    error "Failed to install $cmd (continuing...)"
    ((FAILED++))
    # Return 0 to continue with next tool instead of stopping
    return 0
}

# ============================================================================
# Package Manager Functions
# ============================================================================

run_brew() {
    # Homebrew should never run as root
    if [[ $EUID -eq 0 ]] && [[ -n "$SUDO_USER" ]]; then
        sudo -u "$SUDO_USER" brew "$@"
    else
        brew "$@"
    fi
}

update_package_manager() {
    log "Updating package manager..."

    case $PACKAGE_MANAGER in
        apt)
            apt-get update -qq || true
            ;;
        pacman)
            pacman -Sy --noconfirm || true
            ;;
        dnf|yum)
            $PACKAGE_MANAGER check-update -q || true
            ;;
        brew)
            run_brew update 2>/dev/null || warn "brew update failed, continuing..."
            ;;
    esac
}

install_package() {
    local package=$1

    case $PACKAGE_MANAGER in
        apt)
            apt-get install -y -qq "$package" || return 1
            ;;
        pacman)
            pacman -S --noconfirm "$package" || return 1
            ;;
        dnf)
            dnf install -y -q "$package" || return 1
            ;;
        yum)
            yum install -y -q "$package" || return 1
            ;;
        brew)
            # On macOS, try brew but handle errors gracefully
            if [[ $EUID -eq 0 ]]; then
                warn "Skipping brew install of $package (running as root)"
                return 1
            else
                brew install "$package" 2>/dev/null || return 1
            fi
            ;;
    esac
}

# ============================================================================
# Prerequisite Installation
# ============================================================================

install_prerequisites() {
    banner "Installing Prerequisites"

    # Essential packages
    local packages="git curl wget unzip jq"

    case $PACKAGE_MANAGER in
        apt)
            packages="$packages build-essential libpcap-dev"
            ;;
        pacman)
            packages="$packages base-devel libpcap"
            ;;
        dnf|yum)
            packages="$packages gcc make libpcap-devel"
            ;;
        brew)
            packages="$packages libpcap"
            ;;
    esac

    for pkg in $packages; do
        log "Installing $pkg..."
        install_package "$pkg" 2>/dev/null || warn "Could not install $pkg"
    done
}

install_go() {
    if command_exists go; then
        GO_VERSION=$(go version | awk '{print $3}')
        log "Go is already installed: $GO_VERSION"
        return 0
    fi

    banner "Installing Go"

    GO_VERSION="1.21.6"

    cd /tmp || return 1

    if [[ "$OS" == "macos" ]]; then
        # Direct download for macOS - don't use Homebrew
        if [[ "$ARCH" == "arm64" ]]; then
            GO_PKG="go${GO_VERSION}.darwin-arm64.tar.gz"
        else
            GO_PKG="go${GO_VERSION}.darwin-amd64.tar.gz"
        fi
        log "Downloading Go for macOS..."
        if ! safe_download "https://go.dev/dl/${GO_PKG}" "${GO_PKG}" 50000000; then
            error "Failed to download Go"
            return 1
        fi
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf "${GO_PKG}"
        rm "${GO_PKG}"

        # Add to shell profiles
        SHELL_PROFILE="$HOME/.zshrc"
        [[ -f "$HOME/.bash_profile" ]] && SHELL_PROFILE="$HOME/.bash_profile"

        if ! grep -q "/usr/local/go/bin" "$SHELL_PROFILE" 2>/dev/null; then
            echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$SHELL_PROFILE"
        fi
    else
        if ! safe_download "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" "go${GO_VERSION}.linux-${ARCH}.tar.gz" 50000000; then
            error "Failed to download Go"
            return 1
        fi
        rm -rf /usr/local/go
        tar -C /usr/local -xzf "go${GO_VERSION}.linux-${ARCH}.tar.gz"
        rm "go${GO_VERSION}.linux-${ARCH}.tar.gz"

        # Add to PATH for Linux
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile.d/go.sh
        echo 'export PATH=$PATH:$HOME/go/bin' >> /etc/profile.d/go.sh
    fi

    export PATH=$PATH:/usr/local/go/bin

    # Set GOPATH for current session
    export GOPATH=${GOPATH:-$HOME/go}
    export PATH=$PATH:$GOPATH/bin

    if command_exists go; then
        log "Go installed successfully: $(go version)"
    else
        error "Go installation failed"
        return 1
    fi
}

install_python_pip() {
    if ! command_exists python3; then
        log "Installing Python3..."
        case $PACKAGE_MANAGER in
            apt)
                apt-get install -y python3 python3-pip python3-venv || true
                ;;
            pacman)
                pacman -S --noconfirm python python-pip || true
                ;;
            dnf|yum)
                $PACKAGE_MANAGER install -y python3 python3-pip || true
                ;;
            brew)
                # macOS usually has Python3, but if not, warn user
                if ! command_exists python3; then
                    warn "Python3 not found. Install with: brew install python3"
                    warn "Or download from: https://www.python.org/downloads/"
                fi
                ;;
        esac
    fi

    # Ensure pip is available
    if ! command_exists pip3; then
        python3 -m ensurepip --upgrade 2>/dev/null || true
    fi

    log "Python3 and pip3 are available"
}

# ============================================================================
# Go Tool Installation Functions
# ============================================================================

install_go_tool() {
    local tool_path=$1
    local binary_name=${2:-$(basename "$tool_path")}

    if $DRY_RUN; then
        info "[DRY RUN] Would install Go tool: $binary_name"
        return 0
    fi

    # Set GOPATH based on user
    if [[ $EUID -eq 0 ]]; then
        export GOPATH=${GOPATH:-/root/go}
    else
        export GOPATH=${GOPATH:-$HOME/go}
    fi
    export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin

    if ! go install "$tool_path@latest" 2>> "$LOG_FILE"; then
        return 1
    fi

    # Copy to system bin if successful
    if [[ -f "$GOPATH/bin/$binary_name" ]]; then
        sudo cp "$GOPATH/bin/$binary_name" "$GO_BIN_PATH/" 2>/dev/null || cp "$GOPATH/bin/$binary_name" "$GO_BIN_PATH/" 2>/dev/null || true
        sudo chmod +x "$GO_BIN_PATH/$binary_name" 2>/dev/null || chmod +x "$GO_BIN_PATH/$binary_name" 2>/dev/null || true
        return 0
    fi

    return 1
}

# ============================================================================
# Individual Tool Installers
# ============================================================================

# Subdomain Enumeration
install_subfinder() {
    install_go_tool "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
}

install_amass() {
    install_go_tool "github.com/owasp-amass/amass/v4/..." "amass"
}

install_assetfinder() {
    install_go_tool "github.com/tomnomnom/assetfinder"
}

install_findomain() {
    if $DRY_RUN; then
        info "[DRY RUN] Would install: findomain"
        return 0
    fi

    cd /tmp || return 1

    # Clean up previous attempts
    rm -f findomain findomain-* 2>/dev/null

    if [[ "$OS" == "macos" ]]; then
        # Try different release formats for macOS
        local download_url=""
        if [[ "$ARCH" == "arm64" ]]; then
            download_url="https://github.com/Findomain/Findomain/releases/latest/download/findomain-aarch64-apple-darwin.zip"
        else
            download_url="https://github.com/Findomain/Findomain/releases/latest/download/findomain-x86_64-apple-darwin.zip"
        fi

        log "Downloading findomain from: $download_url"
        if safe_download "$download_url" "findomain.zip" 100000; then
            unzip -o findomain.zip 2>/dev/null
            # Find the binary (might be in current dir or extracted with different name)
            local binary=$(find . -maxdepth 1 -name "findomain*" -type f -perm +111 2>/dev/null | head -1)
            if [[ -z "$binary" ]]; then
                binary=$(find . -maxdepth 1 -name "findomain*" ! -name "*.zip" -type f 2>/dev/null | head -1)
            fi
            if [[ -n "$binary" ]]; then
                chmod +x "$binary"
                sudo mv "$binary" "$GO_BIN_PATH/findomain"
                rm -f findomain.zip
                return 0
            fi
        fi

        # Fallback: try cargo install
        if command_exists cargo; then
            log "Trying cargo install for findomain..."
            cargo install findomain 2>> "$LOG_FILE" && return 0
        fi

        error "Could not install findomain on macOS"
        return 1
    else
        # Linux - try multiple formats
        local download_url="https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip"
        if safe_download "$download_url" "findomain.zip" 100000; then
            unzip -o findomain.zip 2>/dev/null
            if [[ -f "findomain" ]]; then
                chmod +x findomain
                mv findomain "$GO_BIN_PATH/"
                rm -f findomain.zip
                return 0
            fi
        fi

        # Try direct binary
        download_url="https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux"
        if safe_download "$download_url" "findomain" 100000; then
            chmod +x findomain
            mv findomain "$GO_BIN_PATH/"
            return 0
        fi

        return 1
    fi

    rm -f findomain* 2>/dev/null
    return 1
}

install_chaos() {
    install_go_tool "github.com/projectdiscovery/chaos-client/cmd/chaos"
}

# HTTP Probing
install_httpx() {
    install_go_tool "github.com/projectdiscovery/httpx/cmd/httpx"
}

install_httprobe() {
    install_go_tool "github.com/tomnomnom/httprobe"
}

# Crawling
install_katana() {
    install_go_tool "github.com/projectdiscovery/katana/cmd/katana"
}

install_gospider() {
    install_go_tool "github.com/jaeles-project/gospider"
}

install_hakrawler() {
    install_go_tool "github.com/hakluke/hakrawler"
}

install_cariddi() {
    install_go_tool "github.com/edoardottt/cariddi/cmd/cariddi"
}

# URL Collection
install_gau() {
    install_go_tool "github.com/lc/gau/v2/cmd/gau"
}

install_waybackurls() {
    install_go_tool "github.com/tomnomnom/waybackurls"
}

install_waymore() {
    if $DRY_RUN; then
        info "[DRY RUN] Would install: waymore"
        return 0
    fi

    # Try pip install first
    if pip3 install waymore 2>> "$LOG_FILE"; then
        return 0
    fi

    # Fallback: clone from GitHub and install
    log "pip install failed, trying git clone method..."
    cd /tmp || return 1
    rm -rf waymore 2>/dev/null

    if git clone https://github.com/xnl-h4ck3r/waymore.git 2>> "$LOG_FILE"; then
        cd waymore || return 1
        if pip3 install . 2>> "$LOG_FILE"; then
            cd /tmp && rm -rf waymore
            return 0
        fi
    fi

    return 1
}

# JS Analysis
install_subjs() {
    install_go_tool "github.com/lc/subjs"
}

install_linkfinder() {
    if $DRY_RUN; then
        info "[DRY RUN] Would install: linkfinder"
        return 0
    fi

    cd /tmp || return 1
    rm -rf LinkFinder 2>/dev/null

    if ! git clone https://github.com/GerbenJavado/LinkFinder.git 2>> "$LOG_FILE"; then
        return 1
    fi

    cd LinkFinder || return 1
    pip3 install -r requirements.txt 2>> "$LOG_FILE" || true
    python3 setup.py install 2>> "$LOG_FILE" || true

    # Create wrapper script
    cat > "$GO_BIN_PATH/linkfinder" << 'EOF'
#!/bin/bash
python3 -m linkfinder "$@"
EOF
    chmod +x "$GO_BIN_PATH/linkfinder"
    return 0
}

install_secretfinder() {
    if $DRY_RUN; then
        info "[DRY RUN] Would install: secretfinder"
        return 0
    fi

    cd /tmp || return 1
    rm -rf SecretFinder 2>/dev/null

    if ! git clone https://github.com/m4ll0k/SecretFinder.git 2>> "$LOG_FILE"; then
        return 1
    fi

    cd SecretFinder || return 1
    pip3 install -r requirements.txt 2>> "$LOG_FILE" || true
    chmod +x SecretFinder.py
    cp SecretFinder.py "$GO_BIN_PATH/secretfinder"
    return 0
}

install_jsubfinder() {
    install_go_tool "github.com/ThreatUnkown/jsubfinder"
}

# Parameter Discovery
install_arjun() {
    if $DRY_RUN; then
        info "[DRY RUN] Would install: arjun"
        return 0
    fi

    # Try pip install first
    if pip3 install arjun 2>> "$LOG_FILE"; then
        return 0
    fi

    # Fallback: clone from GitHub and install
    log "pip install failed, trying git clone method..."
    cd /tmp || return 1
    rm -rf Arjun 2>/dev/null

    if git clone https://github.com/s0md3v/Arjun.git 2>> "$LOG_FILE"; then
        cd Arjun || return 1
        if pip3 install . 2>> "$LOG_FILE"; then
            cd /tmp && rm -rf Arjun
            return 0
        fi
    fi

    return 1
}

install_x8() {
    if $DRY_RUN; then
        info "[DRY RUN] Would install: x8"
        return 0
    fi

    cd /tmp || return 1
    rm -f x8* 2>/dev/null

    local download_url=""
    if [[ "$OS" == "macos" ]]; then
        if [[ "$ARCH" == "arm64" ]]; then
            download_url="https://github.com/Sh1Yo/x8/releases/latest/download/x8_darwin_arm64.gz"
        else
            download_url="https://github.com/Sh1Yo/x8/releases/latest/download/x8_darwin_amd64.gz"
        fi
    else
        download_url="https://github.com/Sh1Yo/x8/releases/latest/download/x8_linux_amd64.gz"
    fi

    if safe_download "$download_url" "x8.gz" 100000; then
        gunzip -f x8.gz
        chmod +x x8
        mv x8 "$GO_BIN_PATH/"
        return 0
    fi

    return 1
}

install_paramspider() {
    if $DRY_RUN; then
        info "[DRY RUN] Would install: paramspider"
        return 0
    fi

    # Try pip install first
    if pip3 install paramspider 2>> "$LOG_FILE"; then
        return 0
    fi

    # Fallback: clone from GitHub and install
    log "pip install failed, trying git clone method..."
    cd /tmp || return 1
    rm -rf paramspider 2>/dev/null

    if git clone https://github.com/devanshbatham/paramspider.git 2>> "$LOG_FILE"; then
        cd paramspider || return 1
        if pip3 install . 2>> "$LOG_FILE"; then
            cd /tmp && rm -rf paramspider
            return 0
        fi
    fi

    return 1
}

# Fuzzing
install_ffuf() {
    install_go_tool "github.com/ffuf/ffuf/v2"
}

install_feroxbuster() {
    if $DRY_RUN; then
        info "[DRY RUN] Would install: feroxbuster"
        return 0
    fi

    cd /tmp || return 1
    rm -f feroxbuster* 2>/dev/null

    if [[ "$OS" == "macos" ]]; then
        # Direct download for macOS
        log "Downloading feroxbuster for macOS..."
        local download_url=""
        if [[ "$ARCH" == "arm64" ]]; then
            download_url="https://github.com/epi052/feroxbuster/releases/latest/download/aarch64-apple-darwin-feroxbuster.zip"
        else
            download_url="https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-apple-darwin-feroxbuster.zip"
        fi

        if safe_download "$download_url" "feroxbuster.zip" 1000000; then
            unzip -o feroxbuster.zip 2>/dev/null
            if [[ -f "feroxbuster" ]]; then
                sudo mv feroxbuster "$GO_BIN_PATH/"
                sudo chmod +x "$GO_BIN_PATH/feroxbuster"
                rm -f feroxbuster.zip
                return 0
            fi
        fi
        return 1
    else
        # Linux - use install script
        curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s "$GO_BIN_PATH" 2>> "$LOG_FILE" || return 1
    fi
}

# Port Scanning
install_naabu() {
    install_go_tool "github.com/projectdiscovery/naabu/v2/cmd/naabu"
}

# Vulnerability Scanning
install_nuclei() {
    install_go_tool "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"

    # Download nuclei templates
    if command_exists nuclei && ! $DRY_RUN; then
        log "Downloading nuclei templates..."
        nuclei -update-templates 2>> "$LOG_FILE" || true
    fi
}

install_jaeles() {
    install_go_tool "github.com/jaeles-project/jaeles"
}

# Subdomain Takeover
install_subjack() {
    install_go_tool "github.com/haccer/subjack"
}

# XSS
install_dalfox() {
    install_go_tool "github.com/hahwul/dalfox/v2"
}

install_xsstrike() {
    if $DRY_RUN; then
        info "[DRY RUN] Would install: xsstrike"
        return 0
    fi

    cd /tmp || return 1
    rm -rf XSStrike 2>/dev/null

    if ! git clone https://github.com/s0md3v/XSStrike.git 2>> "$LOG_FILE"; then
        return 1
    fi

    cd XSStrike || return 1
    pip3 install -r requirements.txt 2>> "$LOG_FILE" || true
    chmod +x xsstrike.py

    # Move to permanent location
    mkdir -p "$INSTALL_DIR"
    cp -r /tmp/XSStrike "$INSTALL_DIR/"

    # Create wrapper
    cat > "$GO_BIN_PATH/xsstrike" << EOF
#!/bin/bash
python3 $INSTALL_DIR/XSStrike/xsstrike.py "\$@"
EOF
    chmod +x "$GO_BIN_PATH/xsstrike"
    return 0
}

install_kxss() {
    install_go_tool "github.com/Emoe/kxss"
}

install_airixss() {
    install_go_tool "github.com/ferreiraklet/airixss"
}

# SQLi
install_sqlmap() {
    if $DRY_RUN; then
        info "[DRY RUN] Would install: sqlmap"
        return 0
    fi

    cd /tmp || return 1
    rm -rf sqlmap 2>/dev/null

    if ! git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git 2>> "$LOG_FILE"; then
        return 1
    fi

    mkdir -p "$INSTALL_DIR"
    cp -r sqlmap "$INSTALL_DIR/"

    # Create wrapper
    cat > "$GO_BIN_PATH/sqlmap" << EOF
#!/bin/bash
python3 $INSTALL_DIR/sqlmap/sqlmap.py "\$@"
EOF
    chmod +x "$GO_BIN_PATH/sqlmap"
    return 0
}

install_ghauri() {
    if $DRY_RUN; then
        info "[DRY RUN] Would install: ghauri"
        return 0
    fi

    # Try pip install first
    if pip3 install ghauri 2>> "$LOG_FILE"; then
        return 0
    fi

    # Fallback: clone from GitHub and install
    log "pip install failed, trying git clone method..."
    cd /tmp || return 1
    rm -rf ghauri 2>/dev/null

    if git clone https://github.com/r0oth3x49/ghauri.git 2>> "$LOG_FILE"; then
        cd ghauri || return 1
        if pip3 install . 2>> "$LOG_FILE"; then
            cd /tmp && rm -rf ghauri
            return 0
        fi
    fi

    return 1
}

# DNS
install_dnsx() {
    install_go_tool "github.com/projectdiscovery/dnsx/cmd/dnsx"
}

install_shuffledns() {
    install_go_tool "github.com/projectdiscovery/shuffledns/cmd/shuffledns"
}

install_puredns() {
    install_go_tool "github.com/d3mondev/puredns/v2"
}

install_massdns() {
    if $DRY_RUN; then
        info "[DRY RUN] Would install: massdns"
        return 0
    fi

    cd /tmp || return 1
    rm -rf massdns 2>/dev/null

    if ! git clone https://github.com/blechschmidt/massdns.git 2>> "$LOG_FILE"; then
        return 1
    fi

    cd massdns || return 1
    if ! make 2>> "$LOG_FILE"; then
        return 1
    fi

    cp bin/massdns "$GO_BIN_PATH/"
    chmod +x "$GO_BIN_PATH/massdns"
    return 0
}

install_dnsgen() {
    if $DRY_RUN; then
        info "[DRY RUN] Would install: dnsgen"
        return 0
    fi

    # Try pip install first
    if pip3 install dnsgen 2>> "$LOG_FILE"; then
        return 0
    fi

    # Fallback: clone from GitHub and install
    log "pip install failed, trying git clone method..."
    cd /tmp || return 1
    rm -rf dnsgen 2>/dev/null

    if git clone https://github.com/ProjectAnte/dnsgen.git 2>> "$LOG_FILE"; then
        cd dnsgen || return 1
        if pip3 install . 2>> "$LOG_FILE"; then
            cd /tmp && rm -rf dnsgen
            return 0
        fi
    fi

    return 1
}

# Reverse DNS
install_hakrevdns() {
    install_go_tool "github.com/hakluke/hakrevdns"
}

install_prips() {
    if $DRY_RUN; then
        info "[DRY RUN] Would install: prips"
        return 0
    fi

    case $PACKAGE_MANAGER in
        apt)
            apt-get install -y prips 2>> "$LOG_FILE" || return 1
            ;;
        *)
            # Build from source for macOS and other systems
            cd /tmp || return 1
            rm -rf prips 2>/dev/null

            if ! git clone https://gitlab.com/prips/prips.git 2>> "$LOG_FILE"; then
                return 1
            fi

            cd prips || return 1
            if ! make 2>> "$LOG_FILE"; then
                return 1
            fi

            sudo cp prips "$GO_BIN_PATH/" 2>/dev/null || cp prips "$GO_BIN_PATH/"
            sudo chmod +x "$GO_BIN_PATH/prips" 2>/dev/null || chmod +x "$GO_BIN_PATH/prips"
            ;;
    esac
    return 0
}

# Cloud
install_cloud_enum() {
    if $DRY_RUN; then
        info "[DRY RUN] Would install: cloud_enum"
        return 0
    fi

    # Try pip install first
    if pip3 install cloud_enum 2>> "$LOG_FILE"; then
        return 0
    fi

    # Fallback: clone from GitHub and install
    log "pip install failed, trying git clone method..."
    cd /tmp || return 1
    rm -rf cloud_enum 2>/dev/null

    if git clone https://github.com/initstring/cloud_enum.git 2>> "$LOG_FILE"; then
        cd cloud_enum || return 1
        pip3 install -r requirements.txt 2>> "$LOG_FILE" || true
        chmod +x cloud_enum.py

        # Create wrapper
        mkdir -p "$INSTALL_DIR"
        cp -r /tmp/cloud_enum "$INSTALL_DIR/"
        cat > "$GO_BIN_PATH/cloud_enum" << EOF
#!/bin/bash
python3 $INSTALL_DIR/cloud_enum/cloud_enum.py "\$@"
EOF
        chmod +x "$GO_BIN_PATH/cloud_enum"
        return 0
    fi

    return 1
}

install_s3scanner() {
    if $DRY_RUN; then
        info "[DRY RUN] Would install: s3scanner"
        return 0
    fi

    # Try pip install first
    if pip3 install s3scanner 2>> "$LOG_FILE"; then
        return 0
    fi

    # Fallback: clone from GitHub and install
    log "pip install failed, trying git clone method..."
    cd /tmp || return 1
    rm -rf S3Scanner 2>/dev/null

    if git clone https://github.com/sa7mon/S3Scanner.git 2>> "$LOG_FILE"; then
        cd S3Scanner || return 1
        if pip3 install . 2>> "$LOG_FILE"; then
            cd /tmp && rm -rf S3Scanner
            return 0
        fi
    fi

    return 1
}

# Git
install_trufflehog() {
    if $DRY_RUN; then
        info "[DRY RUN] Would install: trufflehog"
        return 0
    fi

    cd /tmp || return 1

    # Use the official install script for both Linux and macOS
    if curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sudo sh -s -- -b "$GO_BIN_PATH" 2>> "$LOG_FILE"; then
        return 0
    fi

    # Fallback: try go install
    install_go_tool "github.com/trufflesecurity/trufflehog/v3"
}

install_github_subdomains() {
    install_go_tool "github.com/gwen001/github-subdomains"
}

# OSINT
install_shodan() {
    if $DRY_RUN; then
        info "[DRY RUN] Would install: shodan"
        return 0
    fi

    # Try pip install first
    if pip3 install shodan 2>> "$LOG_FILE"; then
        return 0
    fi

    # Fallback: install from git
    log "pip install failed, trying git install..."
    if pip3 install git+https://github.com/achillean/shodan-python.git 2>> "$LOG_FILE"; then
        return 0
    fi

    return 1
}

install_censys() {
    if $DRY_RUN; then
        info "[DRY RUN] Would install: censys"
        return 0
    fi

    # Try pip install first
    if pip3 install censys 2>> "$LOG_FILE"; then
        return 0
    fi

    # Fallback: install from git
    log "pip install failed, trying git install..."
    if pip3 install git+https://github.com/censys/censys-python.git 2>> "$LOG_FILE"; then
        return 0
    fi

    return 1
}

install_metabigor() {
    install_go_tool "github.com/j3ssie/metabigor"
}

# Screenshots
install_gowitness() {
    install_go_tool "github.com/sensepost/gowitness"
}

install_eyewitness() {
    if $DRY_RUN; then
        info "[DRY RUN] Would install: eyewitness"
        return 0
    fi

    cd /tmp || return 1
    rm -rf EyeWitness 2>/dev/null

    if ! git clone https://github.com/RedSiege/EyeWitness.git 2>> "$LOG_FILE"; then
        return 1
    fi

    cd EyeWitness/Python || return 1
    pip3 install -r requirements.txt 2>> "$LOG_FILE" || true

    mkdir -p "$INSTALL_DIR"
    cp -r /tmp/EyeWitness "$INSTALL_DIR/"

    # Create wrapper
    cat > "$GO_BIN_PATH/eyewitness" << EOF
#!/bin/bash
python3 $INSTALL_DIR/EyeWitness/Python/EyeWitness.py "\$@"
EOF
    chmod +x "$GO_BIN_PATH/eyewitness"
    return 0
}

# Certificate Monitoring
install_certstream() {
    if $DRY_RUN; then
        info "[DRY RUN] Would install: certstream"
        return 0
    fi

    # Try pip install first
    if pip3 install certstream 2>> "$LOG_FILE"; then
        return 0
    fi

    # Fallback: install from git
    log "pip install failed, trying git install..."
    if pip3 install git+https://github.com/CaliDog/certstream-python.git 2>> "$LOG_FILE"; then
        return 0
    fi

    return 1
}

# Other useful tools
install_anew() {
    install_go_tool "github.com/tomnomnom/anew"
}

install_unfurl() {
    install_go_tool "github.com/tomnomnom/unfurl"
}

install_qsreplace() {
    install_go_tool "github.com/tomnomnom/qsreplace"
}

# ============================================================================
# Wordlist Installation
# ============================================================================

install_wordlists() {
    banner "Installing Wordlists"

    if $DRY_RUN; then
        info "[DRY RUN] Would install wordlists"
        return 0
    fi

    WORDLIST_DIR="/opt/wordlists"
    mkdir -p "$WORDLIST_DIR" 2>/dev/null || sudo mkdir -p "$WORDLIST_DIR"

    # SecLists
    if [[ ! -d "$WORDLIST_DIR/SecLists" ]]; then
        log "Downloading SecLists..."
        git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$WORDLIST_DIR/SecLists" 2>> "$LOG_FILE" || warn "Failed to download SecLists"
    else
        info "SecLists already installed"
    fi

    # Assetnote wordlists
    if [[ ! -f "$WORDLIST_DIR/best-dns-wordlist.txt" ]]; then
        log "Downloading Assetnote DNS wordlist..."
        wget -q -O "$WORDLIST_DIR/best-dns-wordlist.txt" \
            "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt" 2>> "$LOG_FILE" || true
    fi

    # Create symlinks for common wordlists
    ln -sf "$WORDLIST_DIR/SecLists/Discovery/Web-Content/common.txt" "$WORDLIST_DIR/common.txt" 2>/dev/null || true
    ln -sf "$WORDLIST_DIR/SecLists/Discovery/Web-Content/raft-medium-directories.txt" "$WORDLIST_DIR/directories.txt" 2>/dev/null || true
    ln -sf "$WORDLIST_DIR/SecLists/Discovery/DNS/subdomains-top1million-5000.txt" "$WORDLIST_DIR/subdomains.txt" 2>/dev/null || true
}

# ============================================================================
# Main Installation Functions
# ============================================================================

install_go_tools() {
    if $SKIP_GO; then
        warn "Skipping Go-based tools"
        return 0
    fi

    banner "Installing Go-based Tools"

    # Subdomain Enumeration
    install_if_missing "subfinder" install_subfinder
    install_if_missing "amass" install_amass
    install_if_missing "assetfinder" install_assetfinder
    install_if_missing "findomain" install_findomain
    install_if_missing "chaos" install_chaos

    # HTTP Probing
    install_if_missing "httpx" install_httpx
    install_if_missing "httprobe" install_httprobe

    # Crawling
    install_if_missing "katana" install_katana
    install_if_missing "gospider" install_gospider
    install_if_missing "hakrawler" install_hakrawler
    install_if_missing "cariddi" install_cariddi

    # URL Collection
    install_if_missing "gau" install_gau
    install_if_missing "waybackurls" install_waybackurls

    # JS Analysis
    install_if_missing "subjs" install_subjs
    install_if_missing "jsubfinder" install_jsubfinder

    # Fuzzing
    install_if_missing "ffuf" install_ffuf
    install_if_missing "feroxbuster" install_feroxbuster

    # Port Scanning
    install_if_missing "naabu" install_naabu

    # Vulnerability Scanning
    install_if_missing "nuclei" install_nuclei
    install_if_missing "jaeles" install_jaeles

    # Subdomain Takeover
    install_if_missing "subjack" install_subjack

    # XSS
    install_if_missing "dalfox" install_dalfox
    install_if_missing "kxss" install_kxss
    install_if_missing "airixss" install_airixss

    # DNS
    install_if_missing "dnsx" install_dnsx
    install_if_missing "shuffledns" install_shuffledns
    install_if_missing "puredns" install_puredns
    install_if_missing "massdns" install_massdns

    # Reverse DNS
    install_if_missing "hakrevdns" install_hakrevdns

    # Git
    install_if_missing "trufflehog" install_trufflehog
    install_if_missing "github-subdomains" install_github_subdomains

    # OSINT
    install_if_missing "metabigor" install_metabigor

    # Screenshots
    install_if_missing "gowitness" install_gowitness

    # Utilities
    install_if_missing "anew" install_anew
    install_if_missing "unfurl" install_unfurl
    install_if_missing "qsreplace" install_qsreplace
}

install_python_tools() {
    if $SKIP_PYTHON; then
        warn "Skipping Python-based tools"
        return 0
    fi

    banner "Installing Python-based Tools"

    # URL Collection
    install_if_missing "waymore" install_waymore

    # JS Analysis
    install_if_missing "linkfinder" install_linkfinder
    install_if_missing "secretfinder" install_secretfinder

    # Parameter Discovery
    install_if_missing "arjun" install_arjun
    install_if_missing "x8" install_x8
    install_if_missing "paramspider" install_paramspider

    # XSS
    install_if_missing "xsstrike" install_xsstrike

    # SQLi
    install_if_missing "sqlmap" install_sqlmap
    install_if_missing "ghauri" install_ghauri

    # DNS
    install_if_missing "dnsgen" install_dnsgen

    # Cloud
    install_if_missing "cloud_enum" install_cloud_enum
    install_if_missing "s3scanner" install_s3scanner

    # OSINT
    install_if_missing "shodan" install_shodan
    install_if_missing "censys" install_censys

    # Screenshots
    install_if_missing "eyewitness" install_eyewitness

    # Certificates
    install_if_missing "certstream" install_certstream
}

install_system_tools() {
    if $SKIP_SYSTEM; then
        warn "Skipping system packages"
        return 0
    fi

    banner "Installing System Tools"

    install_if_missing "prips" install_prips
}

# ============================================================================
# Verification
# ============================================================================

verify_installation() {
    banner "Verifying Installation"

    local tools=(
        "subfinder" "amass" "assetfinder" "findomain" "chaos"
        "httpx" "httprobe"
        "katana" "gospider" "hakrawler" "cariddi"
        "gau" "waybackurls" "waymore"
        "subjs" "linkfinder" "secretfinder" "jsubfinder"
        "arjun" "x8" "paramspider"
        "ffuf" "feroxbuster"
        "naabu"
        "nuclei" "jaeles" "subjack"
        "dalfox" "xsstrike" "kxss" "airixss"
        "sqlmap" "ghauri"
        "dnsx" "shuffledns" "puredns" "massdns" "dnsgen"
        "hakrevdns" "prips"
        "cloud_enum" "s3scanner"
        "trufflehog" "github-subdomains"
        "shodan" "censys" "metabigor"
        "gowitness" "eyewitness"
        "certstream"
        "anew" "unfurl" "qsreplace"
    )

    local available=0
    local missing=0
    local missing_list=""

    for tool in "${tools[@]}"; do
        if command_exists "$tool"; then
            ((available++))
        else
            ((missing++))
            missing_list="$missing_list $tool"
        fi
    done

    echo ""
    echo -e "${GREEN}Available tools: $available${NC}"
    echo -e "${RED}Missing tools: $missing${NC}"

    if [[ $missing -gt 0 ]]; then
        echo -e "${YELLOW}Missing:${NC}$missing_list"
    fi

    echo ""
}

# ============================================================================
# Usage & Help
# ============================================================================

show_help() {
    echo "ReconTool - Automated Tool Installer"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --no-go       Skip Go-based tools"
    echo "  --no-python   Skip Python-based tools"
    echo "  --no-system   Skip system packages"
    echo "  --dry-run     Show what would be installed"
    echo "  --help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  # On macOS (run WITHOUT sudo):"
    echo "  ./$0"
    echo "  ./$0 --dry-run"
    echo ""
    echo "  # On Linux (run WITH sudo):"
    echo "  sudo $0"
    echo "  sudo $0 --dry-run"
    echo "  sudo $0 --no-python"
    echo ""
}

# ============================================================================
# Main
# ============================================================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --no-go)
                SKIP_GO=true
                shift
                ;;
            --no-python)
                SKIP_PYTHON=true
                shift
                ;;
            --no-system)
                SKIP_SYSTEM=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # Header
    banner "ReconTool - Automated Tool Installer"

    if $DRY_RUN; then
        warn "DRY RUN MODE - No changes will be made"
    fi

    # Detect system FIRST (before root check)
    detect_os
    detect_arch

    # Check permissions (skip for dry run)
    if ! $DRY_RUN; then
        check_root
    fi

    # Initialize log
    echo "ReconTool Installation Log - $(date)" > "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/recontool_install_$$.log"
    echo "ReconTool Installation Log - $(date)" > "$LOG_FILE"

    # Create directories (use sudo if needed)
    sudo mkdir -p "$GO_BIN_PATH" "$INSTALL_DIR" 2>/dev/null || mkdir -p "$GO_BIN_PATH" "$INSTALL_DIR" 2>/dev/null || true

    if ! $DRY_RUN; then
        # Install prerequisites
        install_prerequisites

        # Install Go
        install_go

        # Install Python/pip
        install_python_pip

        # Update package manager (skip for brew on root)
        if [[ "$PACKAGE_MANAGER" != "brew" ]] || [[ $EUID -ne 0 ]]; then
            update_package_manager
        fi
    fi

    # Install tools
    install_go_tools
    install_python_tools
    install_system_tools

    # Install wordlists
    install_wordlists

    # Verify installation
    verify_installation

    # Summary
    banner "Installation Complete"
    echo -e "${GREEN}Installed: $INSTALLED${NC}"
    echo -e "${YELLOW}Skipped (already installed): $SKIPPED${NC}"
    echo -e "${RED}Failed: $FAILED${NC}"
    echo ""
    echo "Log file: $LOG_FILE"
    echo ""

    if [[ $FAILED -gt 0 ]]; then
        warn "Some tools failed to install. Check $LOG_FILE for details."
        warn "The script continued with other installations."
    fi

    log "Installation process completed!"

    # Remind about PATH
    echo -e "${CYAN}NOTE: You may need to restart your shell or run:${NC}"
    echo "  export PATH=\$PATH:$GO_BIN_PATH:/usr/local/go/bin:\$HOME/go/bin"
    echo ""
}

# Run main
main "$@"
