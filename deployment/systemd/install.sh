#!/bin/bash
#
# AVA gRPC - Systemd Service Installation
#

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo "================================================"
echo "  AVA gRPC - Systemd Service Installation"
echo "================================================"
echo ""

# Root-Check
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}❌ Dieses Script muss als root ausgeführt werden${NC}"
   exit 1
fi

# User erstellen
create_user() {
    if id "ava" &>/dev/null; then
        echo -e "${GREEN}✅ User 'ava' existiert bereits${NC}"
    else
        echo -e "${YELLOW}👤 Erstelle User 'ava'...${NC}"
        useradd -r -s /bin/bash -d /opt/ava -m ava
        echo -e "${GREEN}✅ User erstellt${NC}"
    fi
}

# Verzeichnisse erstellen
create_directories() {
    echo -e "${YELLOW}📁 Erstelle Verzeichnisse...${NC}"
    
    mkdir -p /opt/ava
    mkdir -p /etc/ava
    mkdir -p /var/log/ava
    mkdir -p /var/lib/ava
    mkdir -p /tmp/ava_certs
    
    chown -R ava:ava /opt/ava /var/log/ava /var/lib/ava /tmp/ava_certs
    chmod 755 /opt/ava /var/log/ava /var/lib/ava
    chmod 700 /etc/ava /tmp/ava_certs
    
    echo -e "${GREEN}✅ Verzeichnisse erstellt${NC}"
}

# Code kopieren
install_code() {
    echo -e "${YELLOW}📦 Installiere AVA...${NC}"
    
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    
    # Virtual Environment erstellen
    if [ ! -d /opt/ava/venv ]; then
        python3 -m venv /opt/ava/venv
    fi
    
    # Dependencies installieren
    /opt/ava/venv/bin/pip install --upgrade pip
    /opt/ava/venv/bin/pip install -e "$SCRIPT_DIR"
    
    # Code kopieren
    rsync -av --delete \
        --exclude='venv' \
        --exclude='__pycache__' \
        --exclude='.git' \
        --exclude='*.pyc' \
        "$SCRIPT_DIR/ava" /opt/ava/
    
    chown -R ava:ava /opt/ava
    
    echo -e "${GREEN}✅ AVA installiert${NC}"
}

# Service-Unit kopieren
install_service() {
    echo -e "${YELLOW}⚙️  Installiere Systemd-Service...${NC}"
    
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    cp "$SCRIPT_DIR/ava-grpc.service" /etc/systemd/system/
    chmod 644 /etc/systemd/system/ava-grpc.service
    
    systemctl daemon-reload
    
    echo -e "${GREEN}✅ Service installiert${NC}"
}

# Env-Datei erstellen
create_env_file() {
    echo -e "${YELLOW}🔧 Erstelle Konfigurationsdatei...${NC}"
    
    if [ ! -f /etc/ava/grpc.env ]; then
        cat > /etc/ava/grpc.env << EOF
# AVA gRPC Server Configuration
AVA_GRPC_BIND=127.0.0.1
AVA_GRPC_PORT=50051
AVA_CERT_DIR=/etc/ava/certs
AVA_LOGLEVEL=INFO

# Secrets (aus Vault oder hier eintragen)
# AVA_GRPC_TOKEN=your-api-key-here
# AVA_JWT_SECRET=your-jwt-secret-here
EOF
        
        chmod 600 /etc/ava/grpc.env
        chown ava:ava /etc/ava/grpc.env
        
        echo -e "${GREEN}✅ Konfigurationsdatei erstellt: /etc/ava/grpc.env${NC}"
        echo -e "${YELLOW}⚠️  Bitte Secrets in /etc/ava/grpc.env eintragen!${NC}"
    else
        echo -e "${GREEN}✅ Konfigurationsdatei existiert bereits${NC}"
    fi
}

# Service aktivieren
enable_service() {
    echo -e "${YELLOW}🚀 Aktiviere Service...${NC}"
    
    systemctl enable ava-grpc.service
    
    echo -e "${GREEN}✅ Service aktiviert${NC}"
    echo ""
    echo "Service starten mit:"
    echo "  systemctl start ava-grpc"
    echo ""
    echo "Status prüfen mit:"
    echo "  systemctl status ava-grpc"
    echo ""
    echo "Logs anzeigen mit:"
    echo "  journalctl -u ava-grpc -f"
}

# Logs konfigurieren
setup_logging() {
    echo -e "${YELLOW}📝 Konfiguriere Logging...${NC}"
    
    # Logrotate
    cat > /etc/logrotate.d/ava-grpc << EOF
/var/log/ava/*.log {
    daily
    rotate 14
    compress
    delaycompress
    notifempty
    missingok
    create 0640 ava ava
    sharedscripts
    postrotate
        systemctl reload ava-grpc.service >/dev/null 2>&1 || true
    endscript
}
EOF
    
    echo -e "${GREEN}✅ Logrotate konfiguriert${NC}"
}

# Hauptausführung
main() {
    create_user
    create_directories
    install_code
    install_service
    create_env_file
    setup_logging
    enable_service
    
    echo ""
    echo "================================================"
    echo -e "${GREEN}✅ Installation abgeschlossen!${NC}"
    echo "================================================"
    echo ""
    echo "Nächste Schritte:"
    echo "  1. Secrets in /etc/ava/grpc.env konfigurieren"
    echo "  2. TLS-Zertifikate in /etc/ava/certs/ ablegen"
    echo "  3. Service starten: systemctl start ava-grpc"
    echo ""
}

# Deinstallation
uninstall() {
    echo -e "${YELLOW}🗑️  Deinstalliere AVA gRPC Service...${NC}"
    
    systemctl stop ava-grpc.service 2>/dev/null || true
    systemctl disable ava-grpc.service 2>/dev/null || true
    
    rm -f /etc/systemd/system/ava-grpc.service
    systemctl daemon-reload
    
    echo -e "${YELLOW}⚠️  Dateien in /opt/ava, /etc/ava, /var/log/ava bleiben erhalten${NC}"
    echo -e "${YELLOW}⚠️  User 'ava' wird nicht gelöscht${NC}"
    
    echo -e "${GREEN}✅ Service deinstalliert${NC}"
}

# Menü
case "${1:-install}" in
    install)
        main
        ;;
    uninstall)
        uninstall
        ;;
    *)
        echo "Usage: $0 [install|uninstall]"
        exit 1
        ;;
esac
