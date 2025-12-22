#!/bin/bash
# Test script for token proxy - repeatable and reliable

set -e  # Exit on error

echo "=========================================="
echo "Token Proxy Test Suite"
echo "=========================================="
echo ""

# Kill any existing port-forward
echo "1. Cleaning up existing port-forwards..."
pkill -f "kubectl port-forward.*token-proxy" 2>/dev/null || true
sleep 2

echo "2. Starting port-forward..."
kubectl port-forward -n ohif-ac svc/token-proxy-service 3000:3000 >/dev/null 2>&1 &
PORT_FORWARD_PID=$!
sleep 3

echo "3. Getting OAuth token..."
TOKEN_RESPONSE=$(curl -s http://localhost:3000/token)
TOKEN=$(echo "$TOKEN_RESPONSE" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
TOKEN_TYPE=$(echo "$TOKEN_RESPONSE" | grep -o '"token_type":"[^"]*"' | cut -d'"' -f4)

echo "   Token type: $TOKEN_TYPE"
echo "   Token length: ${#TOKEN} characters"
echo ""

echo "4. Testing VNA proxy..."
VNA_RESPONSE=$(curl -s "http://localhost:3000/proxy/rpvna-dev/rp/vna/query/studies?limit=2")
RESPONSE_SIZE=${#VNA_RESPONSE}

echo "   Response size: $RESPONSE_SIZE bytes"
echo "   First 200 bytes:"
echo "$VNA_RESPONSE" | head -c 200
echo ""
echo ""

echo "5. Cleanup..."
#kill $PORT_FORWARD_PID 2>/dev/null || true

echo "=========================================="
echo "Test complete!"
echo "=========================================="
