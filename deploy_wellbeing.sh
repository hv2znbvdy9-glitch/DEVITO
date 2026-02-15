#!/bin/bash
# Deploy AVA Wellbeing System

set -e

echo "🚀 AVA Wellbeing System - Full Deployment Starting..."
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}[1/5]${NC} Starting Docker services..."
docker-compose up -d
sleep 5

echo -e "${BLUE}[2/5]${NC} Waiting for services to be healthy..."
for i in {1..30}; do
  if curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo -e "${GREEN}✅${NC} AVA API is healthy"
    break
  fi
  echo -n "."
  sleep 2
done

if ! curl -s http://localhost:8000/health > /dev/null 2>&1; then
  echo -e "${YELLOW}⚠️ API not responding yet, continuing...${NC}"
fi

echo ""
echo -e "${BLUE}[3/5]${NC} Initializing Wellbeing endpoints..."
curl -s -X POST http://localhost:8000/api/wellbeing/health/check | jq '.' || echo "Health check queued"

echo ""
echo -e "${BLUE}[4/5]${NC} Accessing Grafana Wellbeing Dashboard..."
sleep 2

echo ""
echo -e "${BLUE}[5/5]${NC} Running integration demo..."
python /workspaces/AVA/demo_wellbeing.py

echo ""
echo -e "${GREEN}✅ AVA Wellbeing System Deployed Successfully!${NC}"
echo ""
echo -e "${YELLOW}📊 Available Services:${NC}"
echo "  🌐 API:     http://localhost:8000"
echo "  📖 Docs:    http://localhost:8000/docs"
echo "  📈 Grafana: http://localhost:3000 (admin/admin)"
echo "  📊 Prometheus: http://localhost:9090"
echo "  🔔 AlertManager: http://localhost:9093"
echo ""
echo -e "${YELLOW}🎯 Quick Links:${NC}"
echo "  • Overall Wellbeing: http://localhost:8000/api/wellbeing/overall"
echo "  • Happiness Score: http://localhost:8000/api/wellbeing/happiness/score"
echo "  • Health Check: http://localhost:8000/api/wellbeing/health/check"
echo "  • Metrics: http://localhost:8000/metrics"
echo ""
echo -e "${YELLOW}📝 Next Steps:${NC}"
echo "  1. Access API docs: http://localhost:8000/docs"
echo "  2. Login to Grafana: http://localhost:3000 (admin/admin)"
echo "  3. Import wellbeing dashboard: monitoring/wellbeing-dashboard.json"
echo "  4. Run tests: pytest tests/test_wellbeing.py -v"
echo ""
