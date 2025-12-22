#!/bin/bash
# Full VNA test through token proxy
set -e

echo "=========================================="
echo "VNA Full Test via Token Proxy"
echo "=========================================="
echo ""

# Cleanup port-forwards
echo "1. Cleanup..."
pkill -f "kubectl port-forward.*token-proxy" 2>/dev/null || true
sleep 2

# Start port-forward
echo "2. Starting port-forward..."
kubectl port-forward -n ohif-ac svc/token-proxy-service 3000:3000 > /tmp/port-forward.log 2>&1 &
PORT_FORWARD_PID=$!
sleep 3

echo "3. Getting OAuth token..."
TOKEN_RESPONSE=$(curl -s http://localhost:3000/token)
TOKEN=$(echo "$TOKEN_RESPONSE" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
echo "   Token acquired (${#TOKEN} chars)"

# Test VNA proxy (30 second timeout)
echo "4. Testing VNA proxy..."
echo "   URL: http://localhost:3000/proxy/rpvna-dev/rp/vna/query/studies?limit=2"
echo ""
timeout 30s wget -q -O- --header="Authorization: Bearer $TOKEN" \
  "http://localhost:3000/proxy/rpvna-dev/rp/vna/query/studies?limit=2" 2>&1 | head -30

EXIT_CODE=$?
if [ $EXIT_CODE -eq 124 ]; then
  echo ""
  echo "   ERROR: Timeout after 30 seconds"
elif [ $EXIT_CODE -ne 0 ]; then
  echo ""
  echo "   ERROR: Exit code $EXIT_CODE"
fi

# Cleanup
echo ""
echo "5. Cleanup..."
kill $PORT_FORWARD_PID 2>/dev/null || true

