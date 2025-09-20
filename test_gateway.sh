#!/bin/bash

# A script to test all endpoints of the API Gateway
# Make sure all mock services and the gateway are running before executing this.

# Define the base URL for our gateway
BASE_URL="http://localhost:8080"

# --- Helper function for printing test results ---
print_result() {
    if [ $1 -eq 0 ]; then
        echo "✅ PASS"
    else
        echo "❌ FAIL"
    fi
    echo "--------------------------------------------------"
}

echo "🚀 Starting API Gateway Integration Tests..."
echo "================================================"

# --- Test 1: Get an authentication token ---
echo "TEST 1: Requesting a JWT token from the Auth service..."
# We use `curl -s` for silent mode, and pipe the output to `jq` to extract the token.
# If you don't have jq, you can install it (e.g., `sudo apt-get install jq`).
TOKEN_RESPONSE=$(curl -s -X POST ${BASE_URL}/api/v1/auth/login)
TOKEN=$(echo ${TOKEN_RESPONSE} | jq -r .token)

# Check if the token was received
if [ -z "$TOKEN" ] || [ "$TOKEN" == "null" ]; then
    echo "Could not retrieve token. Response: ${TOKEN_RESPONSE}"
    print_result 1
    exit 1
else
    echo "Successfully retrieved token: ${TOKEN}"
    print_result 0
fi

# --- Test 2: Access a protected route WITHOUT a token ---
echo "TEST 2: Accessing /appointments without a token (should fail with 401)..."
# We use `-o /dev/null` to discard the body, and `-w "%{http_code}"` to only output the status code.
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" ${BASE_URL}/api/v1/appointments/)
echo "Received HTTP Status: ${HTTP_STATUS}"
test ${HTTP_STATUS} -eq 401
print_result $?

# --- Test 3: Access a protected route WITH an INVALID token ---
echo "TEST 3: Accessing /appointments with an invalid token (should fail with 401)..."
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer invalid-token-string" ${BASE_URL}/api/v1/appointments/)
echo "Received HTTP Status: ${HTTP_STATUS}"
test ${HTTP_STATUS} -eq 401
print_result $?

# --- Test 4: Access protected routes WITH a VALID token ---
# We will now test all protected endpoints. They should all return 200.
PROTECTED_ENDPOINTS=(
    "/api/v1/appointments/"
    "/api/v1/services/status"
    "/api/v1/ws/"
    "/api/v1/ai/query"
)

echo "TEST 4: Accessing all protected endpoints with a valid token (should succeed with 200)..."
ALL_PASS=true
for endpoint in "${PROTECTED_ENDPOINTS[@]}"; do
    echo "  -> Testing ${endpoint}..."
    HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${TOKEN}" "${BASE_URL}${endpoint}")
    echo "     Received HTTP Status: ${HTTP_STATUS}"
    if [ ${HTTP_STATUS} -ne 200 ]; then
        ALL_PASS=false
    fi
done

# Final check for the group of tests
test "$ALL_PASS" = true
print_result $?

echo "🎉 All tests completed."