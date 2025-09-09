# TK Smart Wallet Deployment Guide

This guide explains how to deploy the TK Smart Wallet contracts to Base network.

## Prerequisites

1. **Foundry**: Make sure you have Foundry installed
2. **Base Network Access**: Ensure you have access to Base network (mainnet or testnet)
3. **Deployment Wallet**: A wallet with sufficient ETH for deployment gas costs

## Setup

1. **Clone and Install Dependencies**:
   ```bash
   git clone <repository-url>
   cd 7702-poc
   forge install
   ```

2. **Create Environment File**:
   Create a `.env` file in the root directory:
   ```bash
   # Your deployment wallet private key (without 0x prefix)
   PRIVATE_KEY=your_private_key_here
   
   # Your deployment wallet address
   DEPLOYER_ADDRESS=your_wallet_address_here
   ```

## Deployment Options

The deployment script supports two deployment modes:

### 1. Standard Deployment (with Manager)
This deploys:
- Mock Contract (for testing)
- Factory Contract
- Manager Contract (with owner)
- Smart Wallet Contract (managed by the manager)

```bash
# Run the main deployment
forge script script/Deploy.s.sol:DeployScript --rpc-url https://mainnet.base.org --broadcast --verify
```

### 2. Deployment Without Manager
This deploys:
- Mock Contract (for testing)
- Factory Contract
- Smart Wallet Contract (direct interaction, no manager)

```bash
# Run deployment without manager
forge script script/Deploy.s.sol:DeployScript --sig "deployWithoutManager()" --rpc-url https://mainnet.base.org --broadcast --verify
```

## Quick Deployment

Use the provided shell script for easy deployment:

```bash
./script/deploy.sh
```

This script will:
- Check for required environment variables
- Build the contracts
- Deploy to Base mainnet
- Save deployment addresses to `deployment.txt`

## Contract Architecture

### With Manager (Standard)
```
Factory → Manager → Smart Wallet
                    ↓
                Mock Contract
```

### Without Manager
```
Factory → Smart Wallet
            ↓
        Mock Contract
```

## Configuration

You can modify the deployment parameters in `script/Deploy.s.sol`:

- `WALLET_NAME`: Name of the smart wallet
- `WALLET_VERSION`: Version of the smart wallet
- `allowedFunctions`: Array of allowed function selectors (empty = all allowed)

## Verification

After deployment, the script will:
1. Verify all contracts are deployed correctly
2. Check that addresses are properly linked
3. Save deployment information to `deployment.txt`

## Post-Deployment

1. **Check deployment.txt** for contract addresses
2. **Verify on BaseScan**: https://basescan.org
3. **Test the contracts** using the provided test files

## Troubleshooting

### Common Issues

1. **Insufficient Gas**: Ensure your wallet has enough ETH for deployment
2. **Invalid Private Key**: Make sure your private key is correct and doesn't include the `0x` prefix
3. **Network Issues**: Check your RPC URL and network connectivity

### Testing

Before deploying to mainnet, test on Base Sepolia:
```bash
forge script script/Deploy.s.sol:DeployScript --rpc-url https://sepolia.base.org --broadcast --verify
```

## Security Notes

- Never commit your `.env` file to version control
- Use a dedicated deployment wallet, not your main wallet
- Test thoroughly on testnet before mainnet deployment
- Review all contract interactions before deployment 