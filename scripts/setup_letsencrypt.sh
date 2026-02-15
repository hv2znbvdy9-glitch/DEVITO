#!/bin/bash
#
# AVA gRPC - Let's Encrypt TLS Certificate Setup
# Automatische Erstellung und Renewal von Production-Zertifikaten
#

set -e

# Konfiguration
DOMAIN="${AVA_GRPC_DOMAIN:-grpc.ava-system.local}"
EMAIL="${AVA_ADMIN_EMAIL:-admin@ava-system.local}"
CERT_DIR="${AVA_CERT_DIR:-/etc/ava/certs}"
WEBROOT="${AVA_WEBROOT:-/var/www/certbot}"
STAGING="${AVA_LETSENCRYPT_STAGING:-false}"

# Farben
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo "================================================"
echo "  AVA gRPC - Let's Encrypt Setup"
echo "================================================"
echo ""
echo "Domain:    $DOMAIN"
echo "Email:     $EMAIL"
echo "Cert Dir:  $CERT_DIR"
echo ""

# Prüfe ob als Root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}❌ Dieses Script muss als root ausgeführt werden${NC}"
   echo "   sudo $0"
   exit 1
fi

# Prüfe ob certbot installiert ist
if ! command -v certbot &> /dev/null; then
    echo -e "${YELLOW}⚙️  Certbot nicht gefunden, installiere...${NC}"
    
    # Betriebssystem erkennen
    if [ -f /etc/debian_version ]; then
        apt-get update
        apt-get install -y certbot
    elif [ -f /etc/redhat-release ]; then
        yum install -y certbot
    else
        echo -e "${RED}❌ Nicht unterstütztes OS${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Certbot installiert${NC}"
fi

# Erstelle Verzeichnisse
mkdir -p "$CERT_DIR"
mkdir -p "$WEBROOT"
mkdir -p /var/log/ava

# ============================================================================
# Methode 1: Standalone (Port 80 muss frei sein)
# ============================================================================

setup_standalone() {
    echo -e "${YELLOW}🔐 Erstelle Zertifikat via Standalone-Methode...${NC}"
    
    EXTRA_ARGS=""
    if [ "$STAGING" = "true" ]; then
        EXTRA_ARGS="--staging"
        echo -e "${YELLOW}⚠️  Staging-Modus aktiviert (Test-Zertifikat)${NC}"
    fi
    
    certbot certonly \
        --standalone \
        --non-interactive \
        --agree-tos \
        --email "$EMAIL" \
        --domains "$DOMAIN" \
        $EXTRA_ARGS
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Zertifikat erfolgreich erstellt${NC}"
        link_certificates
    else
        echo -e "${RED}❌ Zertifikat-Erstellung fehlgeschlagen${NC}"
        exit 1
    fi
}

# ============================================================================
# Methode 2: Webroot (für laufende Webserver)
# ============================================================================

setup_webroot() {
    echo -e "${YELLOW}🔐 Erstelle Zertifikat via Webroot-Methode...${NC}"
    
    EXTRA_ARGS=""
    if [ "$STAGING" = "true" ]; then
        EXTRA_ARGS="--staging"
    fi
    
    certbot certonly \
        --webroot \
        --webroot-path "$WEBROOT" \
        --non-interactive \
        --agree-tos \
        --email "$EMAIL" \
        --domains "$DOMAIN" \
        $EXTRA_ARGS
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Zertifikat erfolgreich erstellt${NC}"
        link_certificates
    else
        echo -e "${RED}❌ Zertifikat-Erstellung fehlgeschlagen${NC}"
        exit 1
    fi
}

# ============================================================================
# Methode 3: DNS Challenge (für interne Domains)
# ============================================================================

setup_dns() {
    echo -e "${YELLOW}🔐 Erstelle Zertifikat via DNS-Challenge...${NC}"
    echo -e "${YELLOW}⚠️  Manuelle DNS-Konfiguration erforderlich!${NC}"
    
    EXTRA_ARGS=""
    if [ "$STAGING" = "true" ]; then
        EXTRA_ARGS="--staging"
    fi
    
    certbot certonly \
        --manual \
        --preferred-challenges dns \
        --email "$EMAIL" \
        --domains "$DOMAIN" \
        $EXTRA_ARGS
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Zertifikat erfolgreich erstellt${NC}"
        link_certificates
    else
        echo -e "${RED}❌ Zertifikat-Erstellung fehlgeschlagen${NC}"
        exit 1
    fi
}

# ============================================================================
# Zertifikate verlinken
# ============================================================================

link_certificates() {
    echo -e "${YELLOW}🔗 Verlinke Zertifikate nach $CERT_DIR...${NC}"
    
    LE_CERT_DIR="/etc/letsencrypt/live/$DOMAIN"
    
    if [ ! -d "$LE_CERT_DIR" ]; then
        echo -e "${RED}❌ Let's Encrypt Zertifikat-Verzeichnis nicht gefunden${NC}"
        exit 1
    fi
    
    # Symlinks erstellen
    ln -sf "$LE_CERT_DIR/fullchain.pem" "$CERT_DIR/server.crt"
    ln -sf "$LE_CERT_DIR/privkey.pem" "$CERT_DIR/server.key"
    ln -sf "$LE_CERT_DIR/chain.pem" "$CERT_DIR/ca.crt"
    
    # Berechtigungen
    chmod 755 "$CERT_DIR"
    chown -h ava:ava "$CERT_DIR"/*.crt "$CERT_DIR"/*.key 2>/dev/null || true
    
    echo -e "${GREEN}✅ Zertifikate verlinkt${NC}"
    echo ""
    echo "Zertifikate verfügbar unter:"
    echo "  • $CERT_DIR/server.crt (Fullchain)"
    echo "  • $CERT_DIR/server.key (Private Key)"
    echo "  • $CERT_DIR/ca.crt (Chain)"
}

# ============================================================================
# Auto-Renewal einrichten
# ============================================================================

setup_autorenewal() {
    echo -e "${YELLOW}🔄 Richte Auto-Renewal ein...${NC}"
    
    # Renewal-Hook erstellen
    cat > /etc/letsencrypt/renewal-hooks/post/ava-grpc-reload.sh << 'EOF'
#!/bin/bash
# AVA gRPC Server nach Cert-Renewal neuladen

systemctl reload ava-grpc.service 2>/dev/null || \
    pkill -SIGHUP -f "ava.api.grpc_server" || \
    echo "⚠️  AVA gRPC Server nicht gefunden"

logger "AVA gRPC: Certificates renewed and reloaded"
EOF
    
    chmod +x /etc/letsencrypt/renewal-hooks/post/ava-grpc-reload.sh
    
    # Cron-Job prüfen (certbot hat eigenen systemd-timer)
    if systemctl is-enabled certbot.timer >/dev/null 2>&1; then
        echo -e "${GREEN}✅ Certbot Timer aktiv (automatisches Renewal)${NC}"
        systemctl status certbot.timer --no-pager | head -n 3
    else
        echo -e "${YELLOW}⚠️  Certbot Timer nicht aktiv, aktiviere...${NC}"
        systemctl enable certbot.timer
        systemctl start certbot.timer
    fi
    
    echo -e "${GREEN}✅ Auto-Renewal konfiguriert${NC}"
}

# ============================================================================
# Zertifikat testen
# ============================================================================

test_certificate() {
    echo -e "${YELLOW}🧪 Teste Zertifikat...${NC}"
    
    if [ -f "$CERT_DIR/server.crt" ]; then
        echo ""
        openssl x509 -in "$CERT_DIR/server.crt" -noout -subject -issuer -dates
        echo ""
        
        # Ablaufdatum prüfen
        EXPIRY=$(openssl x509 -in "$CERT_DIR/server.crt" -noout -enddate | cut -d= -f2)
        EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s)
        NOW_EPOCH=$(date +%s)
        DAYS_LEFT=$(( ($EXPIRY_EPOCH - $NOW_EPOCH) / 86400 ))
        
        if [ $DAYS_LEFT -lt 30 ]; then
            echo -e "${YELLOW}⚠️  Zertifikat läuft in $DAYS_LEFT Tagen ab!${NC}"
        else
            echo -e "${GREEN}✅ Zertifikat gültig für $DAYS_LEFT Tage${NC}"
        fi
    else
        echo -e "${RED}❌ Zertifikat nicht gefunden${NC}"
    fi
}

# ============================================================================
# Hauptmenü
# ============================================================================

if [ "$1" = "--standalone" ]; then
    setup_standalone
    setup_autorenewal
    test_certificate
elif [ "$1" = "--webroot" ]; then
    setup_webroot
    setup_autorenewal
    test_certificate
elif [ "$1" = "--dns" ]; then
    setup_dns
    setup_autorenewal
    test_certificate
elif [ "$1" = "--renew" ]; then
    echo -e "${YELLOW}🔄 Erneuere Zertifikate...${NC}"
    certbot renew
    test_certificate
elif [ "$1" = "--test" ]; then
    test_certificate
else
    echo "Usage: $0 [--standalone|--webroot|--dns|--renew|--test]"
    echo ""
    echo "Methoden:"
    echo "  --standalone  Port 80 wird temporär genutzt (Server muss gestoppt sein)"
    echo "  --webroot     Nutzt existierenden Webserver"
    echo "  --dns         Manuelle DNS-Challenge (für interne Domains)"
    echo "  --renew       Erneuere existierende Zertifikate"
    echo "  --test        Teste existierende Zertifikate"
    echo ""
    echo "Umgebungsvariablen:"
    echo "  AVA_GRPC_DOMAIN           Domain für Zertifikat"
    echo "  AVA_ADMIN_EMAIL           Admin-Email für Let's Encrypt"
    echo "  AVA_CERT_DIR              Ziel-Verzeichnis"
    echo "  AVA_LETSENCRYPT_STAGING   'true' für Test-Zertifikate"
    exit 1
fi

echo ""
echo "================================================"
echo -e "${GREEN}✅ Setup abgeschlossen!${NC}"
echo "================================================"
