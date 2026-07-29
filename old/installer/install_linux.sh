#!/bin/bash
# =============================================================================
# SecureSeaHorse SIEM v3.0.0 -- Linux Installer
# =============================================================================
# Usage:
#   sudo ./install_linux.sh server    # Install server only
#   sudo ./install_linux.sh client    # Install client only
#   sudo ./install_linux.sh both      # Install both
#   sudo ./install_linux.sh uninstall # Remove everything
#   sudo ./install_linux.sh build     # Build from source and install
#   sudo ./install_linux.sh certs     # Generate self-signed TLS certs
# =============================================================================

set -e

VERSION="3.0.0"
PREFIX="/opt/seahorse"
SERVICE_USER="seahorse"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

log()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()   { echo -e "${YELLOW}[!]${NC} $1"; }
error()  { echo -e "${RED}[!]${NC} $1"; exit 1; }
header() { echo -e "\n${BLUE}=== $1 ===${NC}\n"; }

check_prereqs() {
    if [ "$(id -u)" -ne 0 ]; then
        error "This installer must be run as root (sudo)."
    fi
    log "Checking prerequisites..."
    for cmd in cmake g++ make openssl; do
        if ! command -v "$cmd" &>/dev/null; then
            warn "$cmd not found. Attempting to install..."
            if command -v apt-get &>/dev/null; then
                apt-get update -qq && apt-get install -y -qq "$cmd" 2>/dev/null || true
            elif command -v yum &>/dev/null; then
                yum install -y -q "$cmd" 2>/dev/null || true
            fi
        fi
    done
    if [ ! -f /usr/include/openssl/ssl.h ] && [ ! -f /usr/local/include/openssl/ssl.h ]; then
        log "Installing OpenSSL development headers..."
        if command -v apt-get &>/dev/null; then
            apt-get install -y -qq libssl-dev 2>/dev/null || true
        elif command -v yum &>/dev/null; then
            yum install -y -q openssl-devel 2>/dev/null || true
        fi
    fi
    if command -v pg_config &>/dev/null; then
        log "PostgreSQL found: $(pg_config --version)"
    else
        warn "PostgreSQL not found. DB features will be disabled (CSV-only mode)."
    fi
}

create_user() {
    if ! id "$SERVICE_USER" &>/dev/null; then
        log "Creating service user: $SERVICE_USER"
        useradd --system --no-create-home --shell /bin/false "$SERVICE_USER"
    else
        log "Service user $SERVICE_USER already exists."
    fi
}

build_from_source() {
    header "Building from Source"
    BUILD_DIR="$SCRIPT_DIR/build"
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    log "Running CMake..."
    cmake "$SCRIPT_DIR" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX"
    log "Compiling..."
    make -j"$(nproc)"
    log "Build complete."
    cd "$SCRIPT_DIR"
}

install_server() {
    header "Installing Server"
    mkdir -p "$PREFIX/server/bin" "$PREFIX/server/config/feeds" \
             "$PREFIX/server/certs" "$PREFIX/server/scripts" \
             "$PREFIX/server/logs" "$PREFIX/server/data"

    if [ -f "$SCRIPT_DIR/build/SeaHorseServer" ]; then
        cp "$SCRIPT_DIR/build/SeaHorseServer" "$PREFIX/server/bin/seahorse-server"
    else
        warn "Server binary not found in build/. Run with 'build' option first."
    fi

    if [ ! -f "$PREFIX/server/config/server.conf" ]; then
        cp "$SCRIPT_DIR/config/server.conf" "$PREFIX/server/config/"
        log "Installed default server.conf"
    else
        cp "$SCRIPT_DIR/config/server.conf" "$PREFIX/server/config/server.conf.new"
        warn "Existing server.conf preserved. New saved as server.conf.new"
    fi
    [ ! -f "$PREFIX/server/config/rules.conf" ] && cp "$SCRIPT_DIR/config/rules.conf" "$PREFIX/server/config/"

    chown -R "$SERVICE_USER:$SERVICE_USER" "$PREFIX/server"
    chmod 750 "$PREFIX/server/bin/seahorse-server" 2>/dev/null || true
    chmod 600 "$PREFIX/server/config/server.conf"
    chmod 700 "$PREFIX/server/certs"

    cat > /etc/systemd/system/seahorse-server.service << EOF
[Unit]
Description=SecureSeaHorse SIEM Server
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$PREFIX/server
ExecStart=$PREFIX/server/bin/seahorse-server --config $PREFIX/server/config/server.conf
Restart=always
RestartSec=10
LimitNOFILE=65535
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$PREFIX/server/logs $PREFIX/server/data
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log "Server installed. Next: place certs in $PREFIX/server/certs/ then: systemctl enable --now seahorse-server"
}

install_client() {
    header "Installing Client Agent"
    mkdir -p "$PREFIX/client/bin" "$PREFIX/client/config" "$PREFIX/client/certs" "$PREFIX/client/logs"

    if [ -f "$SCRIPT_DIR/build/SeaHorseClient" ]; then
        cp "$SCRIPT_DIR/build/SeaHorseClient" "$PREFIX/client/bin/seahorse-client"
    else
        warn "Client binary not found in build/. Run with 'build' option first."
    fi

    if [ ! -f "$PREFIX/client/config/client.conf" ]; then
        cp "$SCRIPT_DIR/config/client.conf" "$PREFIX/client/config/"
    else
        cp "$SCRIPT_DIR/config/client.conf" "$PREFIX/client/config/client.conf.new"
    fi

    chown -R root:root "$PREFIX/client"
    chmod 750 "$PREFIX/client/bin/seahorse-client" 2>/dev/null || true
    chmod 600 "$PREFIX/client/config/client.conf"
    chmod 700 "$PREFIX/client/certs"

    cat > /etc/systemd/system/seahorse-client.service << EOF
[Unit]
Description=SecureSeaHorse SIEM Agent
After=network.target

[Service]
Type=simple
ExecStart=$PREFIX/client/bin/seahorse-client --config $PREFIX/client/config/client.conf
Restart=always
RestartSec=10
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    log "Client installed. Next: place certs + set server_host, then: systemctl enable --now seahorse-client"
}

do_uninstall() {
    header "Uninstalling SecureSeaHorse"
    systemctl stop seahorse-server seahorse-client 2>/dev/null || true
    systemctl disable seahorse-server seahorse-client 2>/dev/null || true
    rm -f /etc/systemd/system/seahorse-{server,client}.service
    systemctl daemon-reload

    warn "Remove $PREFIX? [y/N]"
    read -r a
    [ "$a" = "y" ] || [ "$a" = "Y" ] && rm -rf "$PREFIX" && log "Removed $PREFIX"

    warn "Remove service user $SERVICE_USER? [y/N]"
    read -r a
    [ "$a" = "y" ] || [ "$a" = "Y" ] && userdel "$SERVICE_USER" 2>/dev/null && log "Removed $SERVICE_USER"

    log "Uninstall complete."
}

generate_certs() {
    header "Generating Self-Signed TLS Certificates"
    CERT_DIR="$PREFIX/certs"
    mkdir -p "$CERT_DIR"

    openssl req -x509 -newkey rsa:4096 -days 365 -nodes \
        -keyout "$CERT_DIR/ca-key.pem" -out "$CERT_DIR/ca.pem" \
        -subj "/CN=SeaHorse-CA/O=SecureSeaHorse/C=US" 2>/dev/null

    openssl req -newkey rsa:2048 -nodes \
        -keyout "$CERT_DIR/server-key.pem" -out "$CERT_DIR/server.csr" \
        -subj "/CN=seahorse-server/O=SecureSeaHorse/C=US" 2>/dev/null
    openssl x509 -req -in "$CERT_DIR/server.csr" \
        -CA "$CERT_DIR/ca.pem" -CAkey "$CERT_DIR/ca-key.pem" \
        -CAcreateserial -days 365 -out "$CERT_DIR/server.pem" 2>/dev/null

    openssl req -newkey rsa:2048 -nodes \
        -keyout "$CERT_DIR/client-key.pem" -out "$CERT_DIR/client.csr" \
        -subj "/CN=seahorse-client/O=SecureSeaHorse/C=US" 2>/dev/null
    openssl x509 -req -in "$CERT_DIR/client.csr" \
        -CA "$CERT_DIR/ca.pem" -CAkey "$CERT_DIR/ca-key.pem" \
        -CAcreateserial -days 365 -out "$CERT_DIR/client.pem" 2>/dev/null

    rm -f "$CERT_DIR"/*.csr "$CERT_DIR"/*.srl
    chmod 600 "$CERT_DIR"/*.pem

    [ -d "$PREFIX/server/certs" ] && cp "$CERT_DIR"/{ca,server,server-key}.pem "$PREFIX/server/certs/" && chown -R "$SERVICE_USER:$SERVICE_USER" "$PREFIX/server/certs/"
    [ -d "$PREFIX/client/certs" ] && cp "$CERT_DIR"/{ca,client,client-key}.pem "$PREFIX/client/certs/"

    log "Certs generated in $CERT_DIR"
    warn "Self-signed certificates are for TESTING ONLY."
}

echo ""
echo "========================================================"
echo "  SecureSeaHorse SIEM v${VERSION} -- Linux Installer"
echo "========================================================"
echo ""

case "${1:-help}" in
    server)    check_prereqs; create_user; install_server ;;
    client)    check_prereqs; install_client ;;
    both)      check_prereqs; create_user; install_server; install_client ;;
    build)     check_prereqs; build_from_source; create_user; install_server; install_client ;;
    certs)     generate_certs ;;
    uninstall) do_uninstall ;;
    *)
        echo "Usage: sudo $0 {server|client|both|build|certs|uninstall}"
        echo "  server     Install server (requires pre-built binary)"
        echo "  client     Install client agent (requires pre-built binary)"
        echo "  both       Install server and client"
        echo "  build      Build from source then install"
        echo "  certs      Generate self-signed TLS certificates"
        echo "  uninstall  Remove all components"
        exit 0 ;;
esac

echo ""
log "Done."
