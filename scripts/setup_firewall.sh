#!/bin/bash
#
# AVA gRPC - Firewall Configuration (iptables)
# Begrenzt Zugriff nur auf autorisierte IPs
#

set -e

# Konfiguration
GRPC_PORT="${AVA_GRPC_PORT:-50051}"
ALLOWED_IPS="${AVA_ALLOWED_IPS:-10.0.0.0/8,172.16.0.0/12,192.168.0.0/16}"
CHAIN_NAME="AVA_GRPC"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo "================================================"
echo "  AVA gRPC - Firewall Setup (iptables)"
echo "================================================"
echo ""
echo "gRPC Port:    $GRPC_PORT"
echo "Allowed IPs:  $ALLOWED_IPS"
echo ""

# Root-Check
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}❌ Dieses Script muss als root ausgeführt werden${NC}"
   exit 1
fi

# ============================================================================
# Firewall-Regeln erstellen
# ============================================================================

setup_firewall() {
    echo -e "${YELLOW}🔥 Konfiguriere Firewall...${NC}"
    
    # Prüfe ob Chain existiert
    if iptables -L "$CHAIN_NAME" -n >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠️  Chain $CHAIN_NAME existiert, lösche alte Regeln...${NC}"
        iptables -F "$CHAIN_NAME"
        iptables -D INPUT -p tcp --dport "$GRPC_PORT" -j "$CHAIN_NAME" 2>/dev/null || true
        iptables -X "$CHAIN_NAME"
    fi
    
    # Neue Chain erstellen
    iptables -N "$CHAIN_NAME"
    
    # Localhost immer erlauben
    iptables -A "$CHAIN_NAME" -s 127.0.0.1 -j ACCEPT
    iptables -A "$CHAIN_NAME" -s ::1 -j ACCEPT
    
    # Autorisierte IPs erlauben
    IFS=',' read -ra IP_ARRAY <<< "$ALLOWED_IPS"
    for ip in "${IP_ARRAY[@]}"; do
        ip=$(echo "$ip" | xargs)  # Trim whitespace
        if [ -n "$ip" ]; then
            iptables -A "$CHAIN_NAME" -s "$ip" -j ACCEPT
            echo -e "   ${GREEN}✅ Erlaubt: $ip${NC}"
        fi
    done
    
    # Rate-Limiting (max 100 connections/min pro IP)
    iptables -A "$CHAIN_NAME" -m state --state NEW -m recent --set --name grpc_rate_limit
    iptables -A "$CHAIN_NAME" -m state --state NEW -m recent --update --seconds 60 --hitcount 100 --name grpc_rate_limit -j LOG --log-prefix "AVA_GRPC_RATE_LIMIT: "
    iptables -A "$CHAIN_NAME" -m state --state NEW -m recent --update --seconds 60 --hitcount 100 --name grpc_rate_limit -j DROP
    
    # Alle anderen blockieren mit Logging
    iptables -A "$CHAIN_NAME" -j LOG --log-prefix "AVA_GRPC_BLOCKED: " --log-level 4
    iptables -A "$CHAIN_NAME" -j REJECT --reject-with tcp-reset
    
    # Chain an INPUT hängen
    iptables -I INPUT -p tcp --dport "$GRPC_PORT" -j "$CHAIN_NAME"
    
    echo -e "${GREEN}✅ Firewall-Regeln aktiviert${NC}"
}

# ============================================================================
# Regeln persistieren
# ============================================================================

save_rules() {
    echo -e "${YELLOW}💾 Speichere Firewall-Regeln...${NC}"
    
    if command -v iptables-save >/dev/null 2>&1; then
        if [ -f /etc/debian_version ]; then
            # Debian/Ubuntu
            iptables-save > /etc/iptables/rules.v4
            echo -e "${GREEN}✅ Regeln gespeichert: /etc/iptables/rules.v4${NC}"
        elif [ -f /etc/redhat-release ]; then
            # RHEL/CentOS
            service iptables save
            echo -e "${GREEN}✅ Regeln gespeichert${NC}"
        fi
    fi
    
    # iptables-persistent installieren (falls nicht vorhanden)
    if [ -f /etc/debian_version ]; then
        if ! dpkg -l | grep -q iptables-persistent; then
            echo -e "${YELLOW}📦 Installiere iptables-persistent...${NC}"
            DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
        fi
    fi
}

# ============================================================================
# Regeln anzeigen
# ============================================================================

show_rules() {
    echo -e "${YELLOW}📋 Aktuelle Firewall-Regeln:${NC}"
    echo ""
    iptables -L "$CHAIN_NAME" -n -v --line-numbers 2>/dev/null || echo "Keine Regeln gefunden"
}

# ============================================================================
# Regeln löschen
# ============================================================================

remove_rules() {
    echo -e "${YELLOW}🗑️  Entferne Firewall-Regeln...${NC}"
    
    if iptables -L "$CHAIN_NAME" -n >/dev/null 2>&1; then
        iptables -D INPUT -p tcp --dport "$GRPC_PORT" -j "$CHAIN_NAME" 2>/dev/null || true
        iptables -F "$CHAIN_NAME"
        iptables -X "$CHAIN_NAME"
        echo -e "${GREEN}✅ Regeln entfernt${NC}"
    else
        echo "Keine Regeln gefunden"
    fi
}

# ============================================================================
# Testen
# ============================================================================

test_rules() {
    echo -e "${YELLOW}🧪 Teste Firewall-Regeln...${NC}"
    echo ""
    
    # Zeige blockierte Connections in Logs
    echo "Letzte blockierte Verbindungen:"
    grep "AVA_GRPC_BLOCKED" /var/log/kern.log 2>/dev/null | tail -n 5 || echo "Keine Blocks bisher"
    
    echo ""
    echo "Rate-Limit-Blocks:"
    grep "AVA_GRPC_RATE_LIMIT" /var/log/kern.log 2>/dev/null | tail -n 5 || echo "Keine Rate-Limits bisher"
}

# ============================================================================
# IP hinzufügen
# ============================================================================

add_ip() {
    local ip="$1"
    
    if [ -z "$ip" ]; then
        echo -e "${RED}❌ Keine IP angegeben${NC}"
        echo "Usage: $0 add-ip <IP/CIDR>"
        exit 1
    fi
    
    echo -e "${YELLOW}➕ Füge IP hinzu: $ip${NC}"
    
    # Regel vor dem REJECT einfügen
    iptables -I "$CHAIN_NAME" 1 -s "$ip" -j ACCEPT
    
    echo -e "${GREEN}✅ IP erlaubt: $ip${NC}"
    save_rules
}

# ============================================================================
# IP entfernen
# ============================================================================

remove_ip() {
    local ip="$1"
    
    if [ -z "$ip" ]; then
        echo -e "${RED}❌ Keine IP angegeben${NC}"
        echo "Usage: $0 remove-ip <IP/CIDR>"
        exit 1
    fi
    
    echo -e "${YELLOW}➖ Entferne IP: $ip${NC}"
    
    iptables -D "$CHAIN_NAME" -s "$ip" -j ACCEPT 2>/dev/null || \
        echo -e "${YELLOW}⚠️  IP nicht in Firewall gefunden${NC}"
    
    save_rules
}

# ============================================================================
# Hauptmenü
# ============================================================================

case "${1:-setup}" in
    setup)
        setup_firewall
        save_rules
        show_rules
        ;;
    remove)
        remove_rules
        ;;
    show)
        show_rules
        ;;
    test)
        test_rules
        ;;
    add-ip)
        add_ip "$2"
        ;;
    remove-ip)
        remove_ip "$2"
        ;;
    save)
        save_rules
        ;;
    *)
        echo "Usage: $0 [setup|remove|show|test|add-ip|remove-ip|save]"
        echo ""
        echo "Commands:"
        echo "  setup        Firewall-Regeln erstellen und aktivieren"
        echo "  remove       Alle Regeln entfernen"
        echo "  show         Aktuelle Regeln anzeigen"
        echo "  test         Firewall testen (Logs prüfen)"
        echo "  add-ip IP    IP zur Whitelist hinzufügen"
        echo "  remove-ip IP IP von Whitelist entfernen"
        echo "  save         Regeln persistent speichern"
        echo ""
        echo "Umgebungsvariablen:"
        echo "  AVA_GRPC_PORT    Port (default: 50051)"
        echo "  AVA_ALLOWED_IPS  Komma-separierte Liste von IPs/CIDRs"
        exit 1
        ;;
esac

echo ""
echo "================================================"
echo -e "${GREEN}✅ Firewall-Konfiguration abgeschlossen!${NC}"
echo "================================================"
