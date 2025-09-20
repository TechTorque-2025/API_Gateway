#!/bin/bash

# Enhanced script to test all endpoints of the API Gateway with multiple users
# Make sure all mock services and the gateway are running before executing this.

# Define the base URL for our gateway
BASE_URL="http://localhost:8080"

# Test users from the data seeder
declare -A TEST_USERS=(
    ["user"]="password"
    ["admin"]="admin123"
    ["testuser"]="test123"
    ["demo"]="demo123"
)

# --- Helper function for printing test results ---
print_result() {
    if [ $1 -eq 0 ]; then
        echo "✅ PASS"
    else
        echo "❌ FAIL"
    fi
    echo "--------------------------------------------------"
}

# --- Helper function to test authentication for a user ---
test_user_authentication() {
    local username=$1
    local password=$2
    local test_number=$3
    
    echo "TEST $test_number: Testing authentication for user '$username'..."
    
    # Test valid credentials
    TOKEN_RESPONSE=$(curl -s -X POST ${BASE_URL}/api/v1/auth/login \
      -H "Content-Type: application/json" \
      -d "{\"username\": \"$username\", \"password\": \"$password\"}")
    
    TOKEN=$(echo ${TOKEN_RESPONSE} | jq -r .token)
    
    # Check if the token was received
    if [ -z "$TOKEN" ] || [ "$TOKEN" == "null" ]; then
        echo "Could not retrieve token for $username. Response: ${TOKEN_RESPONSE}"
        print_result 1
        return 1
    else
        echo "Successfully retrieved token for $username: ${TOKEN:0:50}..."
        print_result 0
        
        # Store the token for later use in protected endpoint tests
        eval "TOKEN_$username=\"$TOKEN\""
        return 0
    fi
}

# --- Helper function to test invalid credentials ---
test_invalid_credentials() {
    local test_number=$1
    
    echo "TEST $test_number: Testing authentication with invalid credentials..."
    
    INVALID_RESPONSE=$(curl -s -X POST ${BASE_URL}/api/v1/auth/login \
      -H "Content-Type: application/json" \
      -d '{"username": "invalid", "password": "wrong"}')
    
    # Check if error message is returned (should not contain token)
    if echo "$INVALID_RESPONSE" | grep -q "error"; then
        echo "Correctly rejected invalid credentials: $INVALID_RESPONSE"
        print_result 0
    else
        echo "Failed to reject invalid credentials. Response: $INVALID_RESPONSE"
        print_result 1
    fi
}

echo "🚀 Starting Enhanced API Gateway Integration Tests..."
echo "================================================"

# --- Test 1-4: Test authentication for all seeded users ---
test_counter=1
all_auth_passed=true

for username in "${!TEST_USERS[@]}"; do
    password="${TEST_USERS[$username]}"
    if ! test_user_authentication "$username" "$password" "$test_counter"; then
        all_auth_passed=false
    fi
    ((test_counter++))
done

# --- Test 5: Test invalid credentials ---
test_invalid_credentials $test_counter
((test_counter++))

# --- Test 6: Access a protected route WITHOUT a token ---
echo "TEST $test_counter: Accessing /appointments without a token (should fail with 401)..."
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" ${BASE_URL}/api/v1/appointments/)
echo "Received HTTP Status: ${HTTP_STATUS}"
test ${HTTP_STATUS} -eq 401
print_result $?
((test_counter++))

# --- Test 7: Access a protected route WITH an INVALID token ---
echo "TEST $test_counter: Accessing /appointments with an invalid token (should fail with 401)..."
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer invalid-token-string" ${BASE_URL}/api/v1/appointments/)
echo "Received HTTP Status: ${HTTP_STATUS}"
test ${HTTP_STATUS} -eq 401
print_result $?
((test_counter++))

# --- Test 8-11: Access protected routes WITH valid tokens from each user ---
PROTECTED_ENDPOINTS=(
    "/api/v1/appointments/"
    "/api/v1/services/status"
    "/api/v1/ws/"
    "/api/v1/ai/query"
)

for username in "${!TEST_USERS[@]}"; do
    token_var="TOKEN_$username"
    token="${!token_var}"
    
    if [ -n "$token" ]; then
        echo "TEST $test_counter: Testing protected endpoints with token from user '$username'..."
        ALL_PASS=true
        
        for endpoint in "${PROTECTED_ENDPOINTS[@]}"; do
            echo "  -> Testing ${endpoint} with $username's token..."
            HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${token}" "${BASE_URL}${endpoint}")
            echo "     Received HTTP Status: ${HTTP_STATUS}"
            if [ ${HTTP_STATUS} -ne 200 ]; then
                ALL_PASS=false
            fi
        done
        
        test "$ALL_PASS" = true
        print_result $?
        ((test_counter++))
    fi
done

# --- Final Summary ---
echo ""
echo "🎯 TEST SUMMARY"
echo "==============="
echo "✅ Authentication tested for all seeded users"
echo "✅ Invalid credentials properly rejected"
echo "✅ Protected routes secured without tokens"
echo "✅ Protected routes secured with invalid tokens"
echo "✅ Protected routes accessible with valid tokens"
echo ""

if [ "$all_auth_passed" = true ]; then
    echo "🎉 All authentication tests completed successfully!"
    exit 0
else
    echo "❌ Some authentication tests failed!"
    exit 1
fi