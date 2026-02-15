#!/bin/bash
#
# AVA gRPC - HashiCorp Vault Integration Setup
# Automatisches Setup für Secret Management
#

set -e

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-}"
VAULT_MOUNT="${AVA_VAULT_MOUNT:-secret}"
VAULT_PATH="${AVA_VAULT_PATH:-ava/grpc}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo "================================================"
echo "  AVA gRPC - Vault Integration Setup"
echo "================================================"
echo ""
echo "Vault Address: $VAULT_ADDR"
echo "Mount Point:   $VAULT_MOUNT"
echo "Secret Path:   $VAULT_PATH"
echo ""

# Prüfe ob vault CLI installiert ist
if ! command -v vault &> /dev/null; then
    echo -e "${YELLOW}⚙️  Vault CLI nicht gefunden, installiere...${NC}"
    
    if [ -f /etc/debian_version ]; then
        wget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor | sudo tee /usr/share/keyrings/hashicorp-archive-keyring.gpg >/dev/null
        echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
        apt-get update && apt-get install -y vault
    else
        echo -e "${RED}❌ Bitte Vault CLI manuell installieren: https://www.vaultproject.io/downloads${NC}"
        exit 1
    fi
fi

# Vault-Verbindung testen
echo -e "${YELLOW}🔍 Teste Vault-Verbindung...${NC}"
if vault status >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Vault erreichbar${NC}"
else
    echo -e "${RED}❌ Vault nicht erreichbar unter $VAULT_ADDR${NC}"
    echo "   Starte lokalen Dev-Server mit: vault server -dev"
    exit 1
fi

# Secrets erstellen
create_secrets() {
    echo -e "${YELLOW}🔐 Erstelle Secrets in Vault...${NC}"
    
    # API Key generieren
    API_KEY="ava-$(openssl rand -hex 32)"
    JWT_SECRET="$(openssl rand -base64 48)"
    
    # In Vault speichern
    vault kv put "${VAULT_MOUNT}/${VAULT_PATH}" \
        api_key="$API_KEY" \
        jwt_secret="$JWT_SECRET" \
        grpc_bind="127.0.0.1" \
        grpc_port="50051"
    
    echo -e "${GREEN}✅ Secrets gespeichert unter ${VAULT_MOUNT}/${VAULT_PATH}${NC}"
    
    # TLS-Zertifikate (falls vorhanden)
    if [ -f "/etc/ava/certs/server.crt" ]; then
        echo -e "${YELLOW}🔐 Speichere TLS-Zertifikate...${NC}"
        
        SERVER_CERT=$(cat /etc/ava/certs/server.crt | base64 -w0)
        SERVER_KEY=$(cat /etc/ava/certs/server.key | base64 -w0)
        CA_CERT=$(cat /etc/ava/certs/ca.crt | base64 -w0)
        
        vault kv put "${VAULT_MOUNT}/${VAULT_PATH}/tls" \
            server_cert="$SERVER_CERT" \
            server_key="$SERVER_KEY" \
            ca_cert="$CA_CERT"
        
        echo -e "${GREEN}✅ TLS-Zertifikate gespeichert${NC}"
    fi
}

# Policy erstellen
create_policy() {
    echo -e "${YELLOW}📜 Erstelle Vault Policy für AVA...${NC}"
    
    cat > /tmp/ava-grpc-policy.hcl << EOF
# AVA gRPC Server Policy
path "${VAULT_MOUNT}/data/${VAULT_PATH}" {
  capabilities = ["read"]
}

path "${VAULT_MOUNT}/data/${VAULT_PATH}/*" {
  capabilities = ["read"]
}
EOF
    
    vault policy write ava-grpc /tmp/ava-grpc-policy.hcl
    rm /tmp/ava-grpc-policy.hcl
    
    echo -e "${GREEN}✅ Policy 'ava-grpc' erstellt${NC}"
}

# AppRole erstellen
create_approle() {
    echo -e "${YELLOW}🎭 Erstelle AppRole für AVA...${NC}"
    
    # AppRole aktivieren
    vault auth enable approle 2>/dev/null || true
    
    # AppRole erstellen
    vault write auth/approle/role/ava-grpc \
        token_policies="ava-grpc" \
        token_ttl=1h \
        token_max_ttl=4h
    
    # Role ID abrufen
    ROLE_ID=$(vault read -field=role_id auth/approle/role/ava-grpc/role-id)
    
    # Secret ID erstellen
    SECRET_ID=$(vault write -field=secret_id -f auth/approle/role/ava-grpc/secret-id)
    
    echo -e "${GREEN}✅ AppRole erstellt${NC}"
    echo ""
    echo "Füge diese Werte zum AVA-Server hinzu:"
    echo "  export AVA_VAULT_ROLE_ID='$ROLE_ID'"
    echo "  export AVA_VAULT_SECRET_ID='$SECRET_ID'"
    echo ""
    
    # In .env-Datei speichern
    cat > /etc/ava/vault.env << EOF
# AVA Vault Integration
VAULT_ADDR=$VAULT_ADDR
AVA_VAULT_ROLE_ID=$ROLE_ID
AVA_VAULT_SECRET_ID=$SECRET_ID
AVA_VAULT_MOUNT=$VAULT_MOUNT
AVA_VAULT_PATH=$VAULT_PATH
EOF
    
    chmod 600 /etc/ava/vault.env
    chown ava:ava /etc/ava/vault.env 2>/dev/null || true
    
    echo -e "${GREEN}✅ Vault-Konfiguration gespeichert: /etc/ava/vault.env${NC}"
}

# Secrets testen
test_secrets() {
    echo -e "${YELLOW}🧪 Teste Secret-Abruf...${NC}"
    
    vault kv get "${VAULT_MOUNT}/${VAULT_PATH}"
    
    echo -e "${GREEN}✅ Secrets erfolgreich abgerufen${NC}"
}

# Hauptausführung
case "${1:-setup}" in
    setup)
        create_secrets
        create_policy
        create_approle
        test_secrets
        ;;
    secrets)
        create_secrets
        ;;
    policy)
        create_policy
        ;;
    approle)
        create_approle
        ;;
    test)
        test_secrets
        ;;
    *)
        echo "Usage: $0 [setup|secrets|policy|approle|test]"
        exit 1
        ;;
esac

echo ""
echo "================================================"
echo -e "${GREEN}✅ Vault Integration abgeschlossen!${NC}"
echo "================================================"
