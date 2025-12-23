#!/bin/bash
# Test script for token proxy - repeatable and reliable

set -euo pipefail

echo "=========================================="
echo "Token Proxy Test Suite"
echo "=========================================="
echo ""

cleanup() {
  if [[ -n "${PORT_FORWARD_PID:-}" ]]; then
    kill "$PORT_FORWARD_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# Kill any existing port-forward
echo "1. Cleaning up existing port-forwards..."
pkill -f "kubectl port-forward.*token-proxy" 2>/dev/null || true
sleep 2

echo "2. Starting port-forward..."
kubectl port-forward -n ohif-ac svc/token-proxy-service 3000:3000 >/dev/null 2>&1 &
PORT_FORWARD_PID=$!
sleep 3

echo "3. Getting OAuth token..."
TOKEN_RESPONSE=$(curl -sS http://localhost:3000/token)
TOKEN=$(echo "$TOKEN_RESPONSE" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
TOKEN_TYPE=$(echo "$TOKEN_RESPONSE" | grep -o '"token_type":"[^"]*"' | cut -d'"' -f4)

echo "   Token type: $TOKEN_TYPE"
echo "   Token length: ${#TOKEN} characters"
echo ""

echo "4. Testing VNA proxy..."
VNA_URL="http://localhost:3000/proxy/rpvna-dev/rp/vna/query/studies?limit=2"
TMP_RESPONSE="/tmp/token-proxy-vna-response.json"
HTTP_CODE=$(curl -sS -o "$TMP_RESPONSE" -w "%{http_code}" "$VNA_URL")
RESPONSE_SIZE=$(wc -c < "$TMP_RESPONSE" | tr -d ' ')

echo "   URL: $VNA_URL"
echo "   HTTP status: $HTTP_CODE"
echo "   Response size: $RESPONSE_SIZE bytes"
if command -v jq >/dev/null 2>&1; then
  echo "   Response preview (first 2 items):"
  jq '.[0:2]' "$TMP_RESPONSE"
else
  echo "   Response preview (first 200 bytes):"
  head -c 200 "$TMP_RESPONSE"
fi
echo ""
echo ""

echo "=========================================="
echo "Test complete!"
echo "=========================================="
