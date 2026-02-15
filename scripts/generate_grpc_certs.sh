#!/bin/bash
#
# AVA gRPC TLS/mTLS Certificate Generation Script
# Erstellt selbstsignierte Zertifikate für Entwicklung und Testing
#
# ACHTUNG: Für Produktion echte Zertifikate von einer CA verwenden!
# (z.B. Let's Encrypt, internes PKI, AWS ACM, etc.)
#

set -e  # Exit on error

# Konfiguration
CERT_DIR="${AVA_CERT_DIR:-./certs}"
VALIDITY_DAYS=365
KEY_SIZE=4096

# Farben für Output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Banner
echo "================================================"
echo "  AVA gRPC Certificate Generation"
echo "================================================"
echo ""

# Prüfe ob openssl installiert ist
if ! command -v openssl &> /dev/null; then
    echo -e "${RED}❌ OpenSSL nicht gefunden!${NC}"
    echo "   Installiere mit: apt-get install openssl"
    exit 1
fi

# Erstelle Cert-Verzeichnis
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

echo -e "${GREEN}📁 Zertifikate werden erstellt in: $(pwd)${NC}"
echo ""

# ============================================================================
# 1. CA (Certificate Authority) erstellen
# ============================================================================

echo -e "${YELLOW}🔐 Schritt 1/4: CA (Certificate Authority) erstellen...${NC}"

# CA Private Key
openssl genrsa -out ca.key $KEY_SIZE 2>/dev/null
chmod 600 ca.key

# CA Certificate (Self-Signed)
openssl req -new -x509 \
    -days $VALIDITY_DAYS \
    -key ca.key \
    -out ca.crt \
    -subj "/C=DE/ST=Berlin/L=Berlin/O=AVA/OU=Security/CN=AVA Root CA" \
    2>/dev/null

echo -e "   ${GREEN}✅ CA-Zertifikat erstellt: ca.crt${NC}"
echo ""

# ============================================================================
# 2. Server-Zertifikat erstellen
# ============================================================================

echo -e "${YELLOW}🔐 Schritt 2/4: Server-Zertifikat erstellen...${NC}"

# Server Private Key
openssl genrsa -out server.key $KEY_SIZE 2>/dev/null
chmod 600 server.key

# Server CSR (Certificate Signing Request)
openssl req -new \
    -key server.key \
    -out server.csr \
    -subj "/C=DE/ST=Berlin/L=Berlin/O=AVA/OU=gRPC/CN=ava-grpc-server" \
    2>/dev/null

# Server Certificate (signiert von CA)
# Mit SAN (Subject Alternative Names) für Hostname-Flexibilität
cat > server_ext.cnf << EOF
subjectAltName = @alt_names
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = localhost
DNS.2 = ava-grpc-server
DNS.3 = *.ava-system.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

openssl x509 -req \
    -in server.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out server.crt \
    -days $VALIDITY_DAYS \
    -extfile server_ext.cnf \
    2>/dev/null

rm server.csr server_ext.cnf

echo -e "   ${GREEN}✅ Server-Zertifikat erstellt: server.crt${NC}"
echo ""

# ============================================================================
# 3. Client-Zertifikat erstellen (für mTLS)
# ============================================================================

echo -e "${YELLOW}🔐 Schritt 3/4: Client-Zertifikat erstellen (mTLS)...${NC}"

# Client Private Key
openssl genrsa -out client.key $KEY_SIZE 2>/dev/null
chmod 600 client.key

# Client CSR
openssl req -new \
    -key client.key \
    -out client.csr \
    -subj "/C=DE/ST=Berlin/L=Berlin/O=AVA/OU=Client/CN=ava-grpc-client" \
    2>/dev/null

# Client Certificate (signiert von CA)
cat > client_ext.cnf << EOF
extendedKeyUsage = clientAuth
EOF

openssl x509 -req \
    -in client.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out client.crt \
    -days $VALIDITY_DAYS \
    -extfile client_ext.cnf \
    2>/dev/null

rm client.csr client_ext.cnf

echo -e "   ${GREEN}✅ Client-Zertifikat erstellt: client.crt${NC}"
echo ""

# ============================================================================
# 4. Verifikation & Info
# ============================================================================

echo -e "${YELLOW}🔍 Schritt 4/4: Zertifikate verifizieren...${NC}"

# Verifiziere Server-Cert gegen CA
if openssl verify -CAfile ca.crt server.crt >/dev/null 2>&1; then
    echo -e "   ${GREEN}✅ Server-Zertifikat gültig${NC}"
else
    echo -e "   ${RED}❌ Server-Zertifikat ungültig!${NC}"
fi

# Verifiziere Client-Cert gegen CA
if openssl verify -CAfile ca.crt client.crt >/dev/null 2>&1; then
    echo -e "   ${GREEN}✅ Client-Zertifikat gültig${NC}"
else
    echo -e "   ${RED}❌ Client-Zertifikat ungültig!${NC}"
fi

echo ""
echo "================================================"
echo -e "${GREEN}✅ Alle Zertifikate erfolgreich erstellt!${NC}"
echo "================================================"
echo ""
echo "Erstellt:"
echo "  • ca.crt         (CA Certificate)"
echo "  • ca.key         (CA Private Key)"
echo "  • server.crt     (Server Certificate)"
echo "  • server.key     (Server Private Key)"
echo "  • client.crt     (Client Certificate)"
echo "  • client.key     (Client Private Key)"
echo ""
echo -e "${YELLOW}⚠️  SICHERHEITSHINWEISE:${NC}"
echo "  1. *.key-Dateien sind PRIVAT → chmod 600, niemals committen!"
echo "  2. Für Produktion: Echte Zertifikate von CA verwenden"
echo "  3. Zertifikate regelmäßig rotieren (Empfehlung: alle 90 Tage)"
echo "  4. ca.key in Vault/HSM speichern, nicht auf Servern"
echo ""
echo -e "${GREEN}Zertifikat-Infos anzeigen:${NC}"
echo "  openssl x509 -in server.crt -text -noout"
echo ""
echo -e "${GREEN}Server starten (in Python):${NC}"
echo "  export AVA_CERT_DIR=$(pwd)"
echo "  python -m ava.api.grpc_server"
echo ""
