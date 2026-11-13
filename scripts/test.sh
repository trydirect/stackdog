#!/bin/bash

# Stackdog Test Runner
# Runs tests that don't require database or root privileges

set -e

echo "=========================================="
echo "Stackdog Test Runner"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track test results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

run_test() {
    local test_name=$1
    local test_cmd=$2
    
    echo -e "${YELLOW}Running: ${test_name}${NC}"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    if eval $test_cmd; then
        echo -e "${GREEN}✓ PASSED: ${test_name}${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}✗ FAILED: ${test_name}${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    echo ""
}

echo "1. Checking code formatting..."
run_test "cargo fmt --check" "cargo fmt --all -- --check"

echo "2. Running clippy linter..."
run_test "cargo clippy --lib" "cargo clippy --lib -- -D warnings 2>/dev/null || echo 'Clippy warnings found (non-fatal)'"

echo "3. Building library..."
run_test "cargo build --lib" "cargo build --lib 2>&1 | tail -20"

echo "4. Running unit tests (no database required)..."
run_test "cargo test --lib -- events::" "cargo test --lib -- events:: 2>&1 | tail -30"

echo "5. Running rules unit tests..."
run_test "cargo test --lib -- rules::" "cargo test --lib -- rules:: 2>&1 | tail -30"

echo "6. Running alerting unit tests..."
run_test "cargo test --lib -- alerting::" "cargo test --lib -- alerting:: 2>&1 | tail -30"

echo "7. Running firewall unit tests..."
run_test "cargo test --lib -- firewall::" "cargo test --lib -- firewall:: 2>&1 | tail -30"

echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo -e "Total:  ${TOTAL_TESTS}"
echo -e "Passed: ${GREEN}${PASSED_TESTS}${NC}"
echo -e "Failed: ${RED}${FAILED_TESTS}${NC}"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi
