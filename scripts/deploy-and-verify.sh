#!/bin/bash

# Deploy and verify TKGasStation on Base and Mainnet
# Usage: ./scripts/deploy-and-verify.sh

set -e

echo "🚀 Starting TKGasStation deployment and verification..."

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

if [ -z "$BASESCAN_API_KEY" ]; then
    echo "❌ BASESCAN_API_KEY not set in .env file"
    exit 1
fi

if [ -z "$ETHERSCAN_API_KEY" ]; then
    echo "❌ ETHERSCAN_API_KEY not set in .env file"
    exit 1
fi

echo "📦 Building contracts..."
forge build

echo "🔍 Testing contracts..."
forge test

echo "🌉 Deploying to Base..."
forge script script/DeployTKGasStation.s.sol:DeployTKGasStation --rpc-url base --broadcast --verify -vvvv

echo "⛓️ Deploying to Ethereum Mainnet..."
forge script script/DeployTKGasStation.s.sol:DeployTKGasStation --rpc-url ethereum --broadcast --verify -vvvv

echo "✅ Deployment and verification complete!"
echo ""
echo "📋 Next steps:"
echo "1. Check the deployment addresses in the output above"
echo "2. Verify contracts on block explorers:"
echo "   - Base: https://basescan.org"
echo "   - Ethereum: https://etherscan.io"
echo "3. Update your frontend with the new contract addresses"
