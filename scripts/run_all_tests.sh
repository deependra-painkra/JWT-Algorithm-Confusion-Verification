#!/bin/bash

# JWT Algorithm Confusion Verification - Complete Test Suite
# Usage: bash run_all_tests.sh

set -e

echo "=========================================="
echo "JWT Verification Suite - Challenge 2"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Step 1: Create directories
echo -e "${YELLOW}[1/4]${NC} Creating directories..."
mkdir -p keys evidence reports scripts
echo -e "${GREEN}✓${NC} Directories created"
echo ""

# Step 2: Generate keys
echo -e "${YELLOW}[2/4]${NC} Generating RSA keypair..."
python3 scripts/generate_test_keys.py
echo ""

# Step 3: Generate tokens
echo -e "${YELLOW}[3/4]${NC} Generating test tokens..."
python3 scripts/generate_test_tokens.py
echo ""

# Step 4: Run verification
echo -e "${YELLOW}[4/4]${NC} Running verification tests..."
python3 scripts/verify_jwt.py --config challenge2_config.json
echo ""

echo -e "${GREEN}=========================================="
echo "Test Suite Complete"
echo "==========================================${NC}"
echo ""
echo "📊 Results saved to:"
echo "   - evidence/jwt_verification_report_*.md"
echo "   - evidence/jwt_verification_results_*.json"
echo "   - evidence/jwt_verification_results_*.sha256"
echo ""
