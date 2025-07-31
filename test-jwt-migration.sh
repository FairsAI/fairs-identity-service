#!/bin/bash

# Test script for Identity Service JWT migration
# Tests both API key and JWT authentication methods

echo "=== Identity Service JWT Migration Test ==="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Base URLs
IDENTITY_URL="http://localhost:3002/api/identity"
AUTH_URL="http://localhost:3005/api/token"

# Test data
TEST_EMAIL="test@example.com"
API_KEY="api-key-1"

echo "1. Testing API Key Authentication (Legacy)"
echo "----------------------------------------"

# Test with API key
RESPONSE=$(curl -s -X POST $IDENTITY_URL/lookup \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"email\": \"$TEST_EMAIL\",
    \"lookupType\": \"email\"
  }")

if echo "$RESPONSE" | grep -q "success"; then
  echo -e "${GREEN}✓ API Key authentication successful${NC}"
  echo "Response: $RESPONSE"
else
  echo -e "${RED}✗ API Key authentication failed${NC}"
  echo "Response: $RESPONSE"
fi

echo ""
echo "2. Testing JWT Service Token Authentication"
echo "----------------------------------------"

# Get service token from Auth Service
echo "Getting service token from Auth Service..."
TOKEN_RESPONSE=$(curl -s -X POST $AUTH_URL/service-token \
  -H "Content-Type: application/json" \
  -d '{
    "service_id": "checkout-service",
    "service_secret": "checkout-service-secret-min-32-chars",
    "audience": ["identity-service"]
  }')

# Extract token
if echo "$TOKEN_RESPONSE" | grep -q "accessToken"; then
  TOKEN=$(echo "$TOKEN_RESPONSE" | grep -o '"accessToken":"[^"]*' | cut -d'"' -f4)
  echo -e "${GREEN}✓ Service token obtained successfully${NC}"
  echo "Token (first 50 chars): ${TOKEN:0:50}..."
else
  echo -e "${RED}✗ Failed to get service token${NC}"
  echo "Response: $TOKEN_RESPONSE"
  exit 1
fi

echo ""
echo "Using JWT token for Identity Service lookup..."

# Test with JWT token
JWT_RESPONSE=$(curl -s -X POST $IDENTITY_URL/lookup \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"email\": \"$TEST_EMAIL\",
    \"lookupType\": \"email\"
  }")

if echo "$JWT_RESPONSE" | grep -q "success"; then
  echo -e "${GREEN}✓ JWT authentication successful${NC}"
  echo "Response: $JWT_RESPONSE"
else
  echo -e "${RED}✗ JWT authentication failed${NC}"
  echo "Response: $JWT_RESPONSE"
fi

echo ""
echo "3. Testing Authentication Monitoring"
echo "-----------------------------------"

# Check auth metrics endpoint (if available)
METRICS_RESPONSE=$(curl -s -X GET $IDENTITY_URL/../metrics/auth \
  -H "x-api-key: $API_KEY")

if [ ! -z "$METRICS_RESPONSE" ]; then
  echo "Authentication metrics:"
  echo "$METRICS_RESPONSE" | jq '.' 2>/dev/null || echo "$METRICS_RESPONSE"
else
  echo -e "${YELLOW}⚠ Metrics endpoint not available${NC}"
fi

echo ""
echo "4. Testing Service Info Headers"
echo "-------------------------------"

# Make request and capture headers
HEADERS=$(curl -s -I -X POST $IDENTITY_URL/lookup \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"email\": \"$TEST_EMAIL\",
    \"lookupType\": \"email\"
  }")

echo "Service authentication headers:"
echo "$HEADERS" | grep -E "X-Service-|X-Request-ID" || echo "No service headers found"

echo ""
echo "=== Test Summary ==="
echo "Both authentication methods should work during the migration period."
echo "API keys will be deprecated once all services are updated to use JWT tokens."
echo ""

# Make script executable
chmod +x $0