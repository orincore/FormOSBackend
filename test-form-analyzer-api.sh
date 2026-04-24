#!/bin/bash

# Test script for Form Analyzer API endpoints
# Make sure the backend server is running before executing this script

BASE_URL="http://localhost:5000/api"
TOKEN=""

echo "=== FormOS Form Analyzer API Test ==="
echo ""

# Step 1: Login to get token
echo "1. Logging in..."
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "pin": "123456"
  }')

TOKEN=$(echo $LOGIN_RESPONSE | grep -o '"token":"[^"]*' | cut -d'"' -f4)

if [ -z "$TOKEN" ]; then
  echo "❌ Login failed. Please create a test user first."
  echo "Response: $LOGIN_RESPONSE"
  exit 1
fi

echo "✅ Login successful"
echo ""

# Step 2: Get user data
echo "2. Fetching user data..."
USER_DATA=$(curl -s -X GET "$BASE_URL/form-analyzer/user-data" \
  -H "Authorization: Bearer $TOKEN")

echo "User Data:"
echo "$USER_DATA" | python3 -m json.tool 2>/dev/null || echo "$USER_DATA"
echo ""

# Step 3: Analyze mock form
echo "3. Analyzing mock form fields..."
ANALYSIS=$(curl -s -X POST "$BASE_URL/form-analyzer/analyze" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "mockFields": ["Full Name", "Date of Birth", "Email", "Phone", "Address", "Company Name"]
  }')

echo "Analysis Result:"
echo "$ANALYSIS" | python3 -m json.tool 2>/dev/null || echo "$ANALYSIS"
echo ""

# Extract key metrics
TOTAL=$(echo $ANALYSIS | grep -o '"totalFields":[0-9]*' | cut -d':' -f2)
MATCHED=$(echo $ANALYSIS | grep -o '"matchedFields":\[[^]]*\]' | grep -o ',' | wc -l)
MATCHED=$((MATCHED + 1))
PERCENTAGE=$(echo $ANALYSIS | grep -o '"matchPercentage":[0-9]*' | cut -d':' -f2)

echo "=== Summary ==="
echo "Total Fields: $TOTAL"
echo "Matched Fields: $MATCHED"
echo "Match Percentage: $PERCENTAGE%"
echo ""
echo "✅ All tests completed!"
