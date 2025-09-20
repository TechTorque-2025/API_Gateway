#!/bin/bash

# Test script that works with current setup (shows the enhanced testing pattern)
# This demonstrates how the script will work once database is integrated

BASE_URL="http://localhost:8080"

# Current working user (when database is integrated, this will test all seeded users)
declare -A TEST_USERS=(
    ["user"]="password"
)

print_result() {
    if [ $1 -eq 0 ]; then
        echo "✅ PASS"
    else
        echo "❌ FAIL"
    fi
    echo "--------------------------------------------------"
}

test_user_authentication() {
    local username=$1
    local password=$2
    local test_number=$3
    
    echo "TEST $test_number: Testing authentication for user '$username'..."
    
    TOKEN_RESPONSE=$(curl -s -X POST ${BASE_URL}/api/v1/auth/login \
      -H "Content-Type: application/json" \
      -d "{\"username\": \"$username\", \"password\": \"$password\"}")
    
    TOKEN=$(echo ${TOKEN_RESPONSE} | jq -r .token)
    
    if [ -z "$TOKEN" ] || [ "$TOKEN" == "null" ]; then
        echo "Could not retrieve token for $username. Response: ${TOKEN_RESPONSE}"
        print_result 1
        return 1
    else
        echo "Successfully retrieved token for $username: ${TOKEN:0:50}..."
        print_result 0
        eval "TOKEN_$username=\"$TOKEN\""
        return 0
    fi
}

echo "🚀 Enhanced Test Script Demonstration..."
echo "========================================"

# Test authentication for working user
test_counter=1
test_user_authentication "user" "password" "$test_counter"
((test_counter++))

# Test invalid credentials
echo "TEST $test_counter: Testing invalid credentials..."
INVALID_RESPONSE=$(curl -s -X POST ${BASE_URL}/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "invalid", "password": "wrong"}')

if echo "$INVALID_RESPONSE" | grep -q "error"; then
    echo "Correctly rejected invalid credentials"
    print_result 0
else
    echo "Failed to reject invalid credentials"
    print_result 1
fi
((test_counter++))

# Test protected endpoints
PROTECTED_ENDPOINTS=(
    "/api/v1/appointments/"
    "/api/v1/services/status"
    "/api/v1/ws/"
    "/api/v1/ai/query"
)

echo "TEST $test_counter: Testing protected endpoints..."
ALL_PASS=true
for endpoint in "${PROTECTED_ENDPOINTS[@]}"; do
    echo "  -> Testing ${endpoint}..."
    HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${TOKEN_user}" "${BASE_URL}${endpoint}")
    echo "     Received HTTP Status: ${HTTP_STATUS}"
    if [ ${HTTP_STATUS} -ne 200 ]; then
        ALL_PASS=false
    fi
done

test "$ALL_PASS" = true
print_result $?

echo ""
echo "🎯 This demonstrates the enhanced testing pattern!"
echo "🔄 Once you restart with database integration, it will test all seeded users."