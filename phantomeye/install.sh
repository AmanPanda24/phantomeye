#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  PhantomEye — Kali Linux Installer
#  Usage: chmod +x install.sh && sudo ./install.sh
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'  

PYTHON_MIN="3.9"

banner() {
cat << "EOF"

  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗███████╗██╗   ██╗███████╗
  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║██╔════╝╚██╗ ██╔╝██╔════╝
  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║█████╗   ╚████╔╝ █████╗
  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║██╔══╝    ╚██╔╝  ██╔══╝
  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║███████╗   ██║   ███████╗
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚══════╝

  AI-Powered OSINT Intelligence Framework — Installer for Kali Linux

EOF
}

info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*"; exit 1; }



check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use sudo)."
    fi
}

check_os() {
    if ! grep -qi "kali\|debian\|ubuntu" /etc/os-release 2>/dev/null; then
        warn "Non-Kali system detected. Installation will proceed but is untested."
    fi
}

check_python() {
    if ! command -v python3 &>/dev/null; then
        error "Python 3 is not installed. Install it with: apt install python3"
    fi

    PYTHON_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    if python3 -c "import sys; exit(0 if sys.version_info >= (3,9) else 1)"; then
        success "Python $PYTHON_VER detected"
    else
        error "Python $PYTHON_MIN+ is required (found $PYTHON_VER)"
    fi
}

install_system_deps() {
    info "Updating package lists…"
    apt-get update -qq

    info "Installing system dependencies…"
    apt-get install -y -qq \
        python3-pip \
        python3-venv \
        libssl-dev \
        libffi-dev \
        python3-dev \
        whois \
        dnsutils \
        nmap \
        curl \
        git

    success "System dependencies installed"
}

setup_venv() {
    INSTALL_DIR="/opt/phantomeye"
    info "Creating installation directory: $INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"
    cp -r . "$INSTALL_DIR/"

    info "Creating Python virtual environment…"
    python3 -m venv "$INSTALL_DIR/venv"

    info "Installing Python dependencies…"
    "$INSTALL_DIR/venv/bin/pip" install --upgrade pip -q
    "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q
    "$INSTALL_DIR/venv/bin/pip" install -e "$INSTALL_DIR" -q

    success "Python environment ready"
}

install_cli_wrapper() {
    WRAPPER="/usr/local/bin/phantomeye"
    info "Installing CLI wrapper to $WRAPPER…"

    cat > "$WRAPPER" << 'WRAPPER_EOF'
#!/usr/bin/env bash
exec /opt/phantomeye/venv/bin/phantomeye "$@"
WRAPPER_EOF

    chmod +x "$WRAPPER"
    success "CLI wrapper installed → phantomeye"
}

setup_config() {
    CONFIG_DIR="$HOME/.phantomeye"
    mkdir -p "$CONFIG_DIR/reports"
    info "Config directory: $CONFIG_DIR"

    if [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
        /opt/phantomeye/venv/bin/phantomeye config --anthropic-key "$ANTHROPIC_API_KEY"
        success "Anthropic API key configured from environment"
    else
        warn "ANTHROPIC_API_KEY not set — AI analysis will be disabled."
        warn "Configure later with: phantomeye config --anthropic-key YOUR_KEY"
    fi
}

verify() {
    if phantomeye --version &>/dev/null; then
        success "PhantomEye installed successfully!"
    else
        error "Installation verification failed. Check the logs above."
    fi
}

print_usage() {
    echo ""
    echo -e "${BOLD}Quick Start:${NC}"
    echo -e "  ${CYAN}phantomeye username johndoe${NC}          # Enumerate username across 30+ platforms"
    echo -e "  ${CYAN}phantomeye email target@email.com${NC}    # Email OSINT + breach check"
    echo -e "  ${CYAN}phantomeye ip 8.8.8.8${NC}               # IP geolocation + ASN + abuse check"
    echo -e "  ${CYAN}phantomeye domain example.com${NC}        # WHOIS + DNS + SSL + tech fingerprint"
    echo -e "  ${CYAN}phantomeye phone +1234567890${NC}         # Phone number OSINT"
    echo -e "  ${CYAN}phantomeye config --show${NC}             # Show current configuration"
    echo -e "  ${CYAN}phantomeye history${NC}                   # List past sessions"
    echo ""
    echo -e "${BOLD}Configure API keys:${NC}"
    echo -e "  ${CYAN}phantomeye config --anthropic-key KEY${NC}   # Enable AI analysis"
    echo -e "  ${CYAN}phantomeye config --hibp-key KEY${NC}        # HaveIBeenPwned"
    echo -e "  ${CYAN}phantomeye config --shodan-key KEY${NC}      # Shodan"
    echo ""
    echo -e "${YELLOW}⚠ For authorized security research only. Always operate within legal boundaries.${NC}"
    echo ""
}

main() {
    banner
    check_root
    check_os
    check_python
    install_system_deps
    setup_venv
    install_cli_wrapper
    setup_config
    verify
    print_usage
}

main "$@"
