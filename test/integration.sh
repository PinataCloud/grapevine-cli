#!/bin/bash

# Simple Grapevine CLI Test - hits every command once
# Requires PRIVATE_KEY environment variable

# Don't exit on error - we want to test everything
set +e

CLI="./grapevine"
PASSED=0
FAILED=0

if [ -z "$PRIVATE_KEY" ]; then
    echo "❌ PRIVATE_KEY environment variable required"
    exit 1
fi

echo "🧪 Testing Grapevine CLI - All Commands"
echo

test_cmd() {
    local name="$1"
    local cmd="$2"
    echo -n "[$((PASSED + FAILED + 1))] $name... "
    
    local output
    output=$(eval "$cmd" 2>&1)
    local exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        echo "✅"
        ((PASSED++))
    else
        echo "❌ (exit: $exit_code)"
        if [ -n "$output" ]; then
            echo "    Error: ${output:0:100}..."
        fi
        ((FAILED++))
    fi
    
    # Small delay to avoid rapid successive requests
    sleep 0.1
}

# Basic commands
test_cmd "CLI help" "$CLI --help"
test_cmd "CLI version" "$CLI version"
test_cmd "CLI info" "$CLI info"

# Categories
test_cmd "List categories" "$CLI categories"

# Auth
ALIAS="test-$(date +%s)"
test_cmd "Auth login" "$CLI auth login --alias $ALIAS --key $PRIVATE_KEY"
test_cmd "Auth status" "$CLI auth status"
test_cmd "Auth list" "$CLI auth list"

# Wallet
test_cmd "Wallet info" "$CLI wallet info"

# Feed operations
echo -n "[$((PASSED + FAILED + 1))] Create feed... "
if FEED_OUTPUT=$($CLI feed create "Test-Feed-$(date +%s)" --description "Test feed" 2>&1); then
    FEED_ID=$(echo "$FEED_OUTPUT" | grep -o 'Feed created: [0-9a-f-]*' | cut -d' ' -f3 | head -1)
    echo "✅ ($FEED_ID)"
    ((PASSED++))
    
    test_cmd "Get feed" "$CLI feed get '$FEED_ID'"
    test_cmd "List feeds" "$CLI feed list --limit 5"
    test_cmd "List my feeds" "$CLI feed myfeeds --limit 5"
    test_cmd "Update feed" "$CLI feed update '$FEED_ID' --description 'Updated description'"
    
    # Entry operations - viewing-free entry (upload always costs, no viewing cost)
    TIMESTAMP=$(date +%s%N)
    echo -n "[$((PASSED + FAILED + 1))] Create viewing-free entry... "
    
    # Use unique content to prevent conflicts
    UNIQUE_CONTENT="Test entry content - timestamp: $TIMESTAMP"
    UNIQUE_TITLE="Test Entry - $TIMESTAMP"
    
    ENTRY_OUTPUT=$($CLI entry add "$FEED_ID" "$UNIQUE_CONTENT" --title "$UNIQUE_TITLE" 2>&1)
    ENTRY_ID=$(echo "$ENTRY_OUTPUT" | grep -o 'Entry created: [0-9a-f-]*' | cut -d' ' -f3 | head -1)
    
    if [ -n "$ENTRY_ID" ]; then
        echo "✅ ($ENTRY_ID)"
        ((PASSED++))
        
        test_cmd "Get entry" "$CLI entry get '$FEED_ID' '$ENTRY_ID'"
        test_cmd "List entries" "$CLI entry list '$FEED_ID' --limit 5"
        
        # Batch entries with unique content
        cat > /tmp/batch.json << EOF
[{"content": "Batch entry 1 - $TIMESTAMP", "title": "Batch 1 - $TIMESTAMP"}, 
 {"content": "Batch entry 2 - $TIMESTAMP", "title": "Batch 2 - $TIMESTAMP"}]
EOF
        test_cmd "Batch create entries" "$CLI entry batch '$FEED_ID' /tmp/batch.json --delay 100"
        
        # Create a viewing-paid entry (costs to view after upload)
        PAID_TIMESTAMP=$(date +%s%N)
        echo -n "[$((PASSED + FAILED + 1))] Create viewing-paid entry... "
        PAID_OUTPUT=$($CLI entry add "$FEED_ID" "Paid entry content - $PAID_TIMESTAMP" --title "Paid Entry - $PAID_TIMESTAMP" --paid --price "50000" 2>&1)
        PAID_ENTRY_ID=$(echo "$PAID_OUTPUT" | grep -o 'Entry created: [0-9a-f-]*' | cut -d' ' -f3 | head -1)
        
        if [ -n "$PAID_ENTRY_ID" ]; then
            echo "✅ ($PAID_ENTRY_ID)"
            ((PASSED++))
            test_cmd "Delete viewing-paid entry" "$CLI entry delete '$FEED_ID' '$PAID_ENTRY_ID' --force"
        else
            echo "❌ (no entry ID found)"
            echo "    Paid entry output: ${PAID_OUTPUT:0:150}..."
            ((FAILED++))
        fi
        
        test_cmd "Delete entry" "$CLI entry delete '$FEED_ID' '$ENTRY_ID' --force"
    else
        echo "❌ (no entry ID found)"
        echo "    Full output: ${ENTRY_OUTPUT}"
        ((FAILED++))
    fi
    
    test_cmd "Delete feed" "$CLI feed delete '$FEED_ID' --force"
else
    echo "❌"
    ((FAILED++))
fi

# Auth cleanup
test_cmd "Auth logout" "$CLI auth logout $ALIAS"

# Cleanup
rm -f /tmp/batch.json

echo
echo "=== RESULTS ==="
echo "✅ Passed: $PASSED"
echo "❌ Failed: $FAILED"
echo "Total: $((PASSED + FAILED))"

if [ $FAILED -eq 0 ]; then
    echo "🎉 ALL COMMANDS WORKING!"
else
    echo "⚠️  Some commands failed"
fi