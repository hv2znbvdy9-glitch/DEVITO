#!/bin/bash

# AVA Wellbeing Dashboard - Automatischer Setup-Script
# Importiert das Wellbeing-Dashboard in Grafana

set -e

GRAFANA_URL="http://localhost:3000"
DASHBOARD_FILE="/workspaces/AVA/monitoring/provisioning/dashboards/wellbeing-dashboard.json"
MAX_RETRIES=30
RETRY_DELAY=2

echo "🌟 AVA Wellbeing Dashboard - Automatischer Setup"
echo "=================================================="

# Warte bis Grafana verfügbar ist
echo "⏳ Warte auf Grafana-Service..."
for i in $(seq 1 $MAX_RETRIES); do
    if curl -s -f "$GRAFANA_URL/api/health" > /dev/null 2>&1; then
        echo "✅ Grafana ist verfügbar!"
        break
    fi
    if [ $i -eq $MAX_RETRIES ]; then
        echo "❌ Grafana nicht erreichbar nach $((MAX_RETRIES * RETRY_DELAY)) Sekunden"
        exit 1
    fi
    echo "   Versuch $i/$MAX_RETRIES..."
    sleep $RETRY_DELAY
done

echo ""
echo "📊 Importiere Wellbeing-Dashboard..."

# Versuche Dashboard zu importieren (unauthentifiziert)
RESPONSE=$(curl -s -X POST "$GRAFANA_URL/api/dashboards/db" \
  -H "Content-Type: application/json" \
  -d @<(python3 << 'PYTHON'
import json
with open('/workspaces/AVA/monitoring/provisioning/dashboards/wellbeing-dashboard.json') as f:
    dashboard = json.load(f)
payload = {"dashboard": dashboard, "overwrite": True}
print(json.dumps(payload))
PYTHON
))

# Parse response
DASHBOARD_ID=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('id', ''))" 2>/dev/null || echo "")
DASHBOARD_UID=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('uid', ''))" 2>/dev/null || echo "")
DASHBOARD_URL=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('url', ''))" 2>/dev/null || echo "")

if [ -n "$DASHBOARD_ID" ] || [ -n "$DASHBOARD_UID" ]; then
    echo "✅ Dashboard erfolgreich importiert!"
    echo ""
    echo "📈 Dashboard-Informationen:"
    echo "   · ID: $DASHBOARD_ID"
    echo "   · UID: $DASHBOARD_UID"
    echo "   · URL: http://localhost:3000$DASHBOARD_URL"
    echo ""
    echo "🌐 Öffne Dashboard im Browser..."
    
    # Bestimme OS und öffne Browser
    if command -v xdg-open &> /dev/null; then
        xdg-open "http://localhost:3000$DASHBOARD_URL" &
    elif command -v open &> /dev/null; then
        open "http://localhost:3000$DASHBOARD_URL" &
    else
        echo "⚠️  Browser nicht automatisch geöffnet - öffne zu Fuß:"
        echo "   http://localhost:3000$DASHBOARD_URL"
    fi
    
    echo ""
    echo "✨ Setup abgeschlossen!"
else
    echo "⚠️  Dashboard-Import-Antwort:"
    echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
    echo ""
    echo "💡 Tipp: Versuche manuell über Grafana-UI:"
    echo "   1. Öffne http://localhost:3000"
    echo "   2. Klick ➕ → Dashboard → Import"
    echo "   3. Wähle: $DASHBOARD_FILE"
fi
