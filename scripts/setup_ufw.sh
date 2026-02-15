#!/bin/bash
#
# AVA gRPC - UFW (Uncomplicated Firewall) Configuration
# Einfachere Alternative zu iptables
#

set -e

GRPC_PORT="${AVA_GRPC_PORT:-50051}"
ALLOWED_IPS="${AVA_ALLOWED_IPS:-}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo "================================================"
echo "  AVA gRPC - Firewall Setup (UFW)"
echo "================================================"
echo ""

# Root-Check
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}❌ Dieses Script muss als root ausgeführt werden${NC}"
   exit 1
fi

# UFW installieren
if ! command -v ufw &> /dev/null; then
    echo -e "${YELLOW}📦 Installiere UFW...${NC}"
    apt-get update && apt-get install -y ufw
fi

# Setup
setup_ufw() {
    echo -e "${YELLOW}🔥 Konfiguriere UFW...${NC}"
    
    # Standard-Policy: Alle eingehenden blockieren
    ufw default deny incoming
    ufw default allow outgoing
    
    # SSH erlauben (wichtig!)
    ufw allow 22/tcp comment "SSH"
    
    # gRPC Port: Standard blockieren
    ufw deny "$GRPC_PORT/tcp" comment "AVA gRPC (default deny)"
    
    # Spezifische IPs erlauben
    if [ -n "$ALLOWED_IPS" ]; then
        IFS=',' read -ra IP_ARRAY <<< "$ALLOWED_IPS"
        for ip in "${IP_ARRAY[@]}"; do
            ip=$(echo "$ip" | xargs)
            if [ -n "$ip" ]; then
                ufw allow from "$ip" to any port "$GRPC_PORT" proto tcp comment "AVA gRPC: $ip"
                echo -e "   ${GREEN}✅ Erlaubt: $ip${NC}"
            fi
        done
    fi
    
    # Localhost
    ufw allow from 127.0.0.1 to any port "$GRPC_PORT" proto tcp comment "AVA gRPC: localhost"
    
    # Rate-Limiting aktivieren
    ufw limit "$GRPC_PORT/tcp" comment "Rate limit"
    
    # UFW aktivieren
    echo -e "${YELLOW}⚙️  Aktiviere UFW...${NC}"
    ufw --force enable
    
    echo -e "${GREEN}✅ UFW konfiguriert und aktiviert${NC}"
}

# Status anzeigen
show_status() {
    echo -e "${YELLOW}📋 UFW Status:${NC}"
    echo ""
    ufw status verbose
}

# IP hinzufügen
add_ip() {
    local ip="$1"
    
    if [ -z "$ip" ]; then
        echo -e "${RED}❌ Keine IP angegeben${NC}"
        exit 1
    fi
    
    ufw allow from "$ip" to any port "$GRPC_PORT" proto tcp comment "AVA gRPC: $ip"
    echo -e "${GREEN}✅ IP erlaubt: $ip${NC}"
}

# IP entfernen
remove_ip() {
    local ip="$1"
    
    if [ -z "$ip" ]; then
        echo -e "${RED}❌ Keine IP angegeben${NC}"
        exit 1
    fi
    
    ufw delete allow from "$ip" to any port "$GRPC_PORT" proto tcp
    echo -e "${GREEN}✅ IP entfernt: $ip${NC}"
}

# Hauptmenü
case "${1:-setup}" in
    setup)
        setup_ufw
        show_status
        ;;
    status)
        show_status
        ;;
    add-ip)
        add_ip "$2"
        ;;
    remove-ip)
        remove_ip "$2"
        ;;
    disable)
        ufw disable
        echo -e "${YELLOW}⚠️  UFW deaktiviert${NC}"
        ;;
    *)
        echo "Usage: $0 [setup|status|add-ip|remove-ip|disable]"
        exit 1
        ;;
esac
