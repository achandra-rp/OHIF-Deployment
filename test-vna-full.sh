#!/bin/bash
# Full VNA test through token proxy
set -euo pipefail

echo "=========================================="
echo "VNA Full Test via Token Proxy"
echo "=========================================="
echo ""

cleanup() {
  if [[ -n "${PORT_FORWARD_PID:-}" ]]; then
    kill "$PORT_FORWARD_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

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
TOKEN_TMP="/tmp/token-proxy-token.json"
TOKEN_HTTP_CODE=$(curl -sS -o "$TOKEN_TMP" -w "%{http_code}" http://localhost:3000/token)
TOKEN_LENGTH=$(grep -o '"access_token":"[^"]*"' "$TOKEN_TMP" | cut -d'"' -f4 | wc -c | tr -d ' ')
echo "   HTTP status: $TOKEN_HTTP_CODE"
echo "   Token length: $TOKEN_LENGTH characters"

# Test VNA proxy (30 second timeout)
echo "4. Testing VNA proxy..."
VNA_URL="http://localhost:3000/proxy/rpvna-dev/rp/vna/query/studies?limit=2"
VNA_TMP="/tmp/token-proxy-vna-response.json"
VNA_HTTP_CODE=$(curl -sS --max-time 30 -o "$VNA_TMP" -w "%{http_code}" "$VNA_URL")
VNA_SIZE=$(wc -c < "$VNA_TMP" | tr -d ' ')
echo "   URL: $VNA_URL"
echo "   HTTP status: $VNA_HTTP_CODE"
echo "   Response size: $VNA_SIZE bytes"
if command -v jq >/dev/null 2>&1; then
  echo "   Response preview (first 2 items):"
  jq '.[0:2]' "$VNA_TMP"
else
  echo "   Response preview (first 200 bytes):"
  head -c 200 "$VNA_TMP"
fi
echo ""

# Cleanup
echo ""
echo "5. Cleanup..."
