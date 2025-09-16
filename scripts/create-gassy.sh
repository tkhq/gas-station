#!/bin/bash

# Script to create Gassy contracts on Base and Ethereum
# Usage: ./scripts/create-gassy.sh [base|ethereum|both] [paymaster_address]

set -e

NETWORK=${1:-both}
PAYMASTER=${2:-0x1234567890123456789012345678901234567890}

echo "🚀 Creating Gassy contracts..."
echo "Network: $NETWORK"
echo "Paymaster: $PAYMASTER"
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
        echo "📦 Creating Gassy on Base..."
        forge script script/CreateGassy.s.sol:CreateGassy --sig "createOnBase(address)" $PAYMASTER --rpc-url base --broadcast -vvvv
        ;;
    "ethereum")
        echo "📦 Creating Gassy on Ethereum..."
        forge script script/CreateGassy.s.sol:CreateGassy --sig "createOnEthereum(address)" $PAYMASTER --rpc-url ethereum --broadcast -vvvv
        ;;
    "both")
        echo "📦 Creating Gassy on both networks..."
        echo ""
        echo "=== Base Network ==="
        forge script script/CreateGassy.s.sol:CreateGassy --sig "createOnBase(address)" $PAYMASTER --rpc-url base --broadcast -vvvv
        echo ""
        echo "=== Ethereum Network ==="
        forge script script/CreateGassy.s.sol:CreateGassy --sig "createOnEthereum(address)" $PAYMASTER --rpc-url ethereum --broadcast -vvvv
        ;;
    *)
        echo "❌ Invalid network. Use: base, ethereum, or both"
        exit 1
        ;;
esac

echo ""
echo "✅ Gassy creation complete!"
echo ""
echo "📋 Next steps:"
echo "1. Use the Gassy contract addresses for 7702 initialization"
echo "2. Users can now initialize their accounts with the Gassy code"
echo "3. Execute transactions with optimized gas costs"
