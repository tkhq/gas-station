#!/bin/bash

# Script to initialize 7702 with Gassy contract
# Usage: ./scripts/init-7702.sh [base|ethereum]

set -e

NETWORK=${1:-ethereum}

echo "🚀 Initializing 7702 with Gassy contract..."
echo "Network: $NETWORK"
echo ""

# Check if .env file exists
if [ ! -f .env ]; then
    echo "❌ .env file not found. Please copy env.example to .env and fill in your values."
    exit 1
fi

# Load environment variables
source .env

# Check required environment variables
if [ -z "$PRIVATE_KEY" ]; then
    echo "❌ PRIVATE_KEY not set in .env file"
    exit 1
fi

case $NETWORK in
    "base")
        echo "📦 Initializing 7702 on Base..."
        forge script script/Init7702.s.sol:Init7702 --sig "initBase()" --rpc-url base --broadcast -vvvv
        ;;
    "ethereum")
        echo "📦 Initializing 7702 on Ethereum..."
        forge script script/Init7702.s.sol:Init7702 --sig "initEthereum()" --rpc-url ethereum --broadcast -vvvv
        ;;
    *)
        echo "❌ Invalid network. Use: base or ethereum"
        exit 1
        ;;
esac

echo ""
echo "✅ 7702 initialization complete!"
echo ""
echo "📋 Next steps:"
echo "1. Your account now has the Gassy contract code"
echo "2. You can call execute() functions directly on your account"
echo "3. Transactions will use the optimized gas costs"
echo ""
echo "🔍 Verify on block explorer:"
if [ "$NETWORK" = "base" ]; then
    echo "Base: https://basescan.org"
else
    echo "Ethereum: https://etherscan.io"
fi
