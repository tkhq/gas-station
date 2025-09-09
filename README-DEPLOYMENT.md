# GassyStation Deployment Guide

This guide will help you deploy the GassyStation contract to Base and Ethereum Mainnet with automatic verification.

## Prerequisites

1. **Foundry installed**: Make sure you have Foundry installed
2. **Private key**: You'll need a private key with ETH for gas fees
3. **API keys**: Get API keys from Basescan and Etherscan for contract verification

## Setup

### 1. Environment Configuration

Copy the example environment file and fill in your values:

```bash
cp env.example .env
```

Edit `.env` with your actual values:

```bash
# Private key for deployment (without 0x prefix)
PRIVATE_KEY=your_private_key_here

# API Keys for contract verification
BASESCAN_API_KEY=your_basescan_api_key_here
ETHERSCAN_API_KEY=your_etherscan_api_key_here
```

### 2. Get API Keys

- **Basescan**: Go to [basescan.org](https://basescan.org) → Sign up → API Keys
- **Etherscan**: Go to [etherscan.io](https://etherscan.io) → Sign up → API Keys

## Deployment

### Option 1: Automated Script (Recommended)

Run the automated deployment script:

```bash
./scripts/deploy-and-verify.sh
```

This will:
- Build the contracts
- Run tests
- Deploy to Base
- Deploy to Ethereum Mainnet
- Verify contracts on both networks

### Option 2: Manual Deployment

#### Deploy to Base

```bash
forge script script/DeployGassyStation.s.sol:DeployGassyStation --rpc-url base --broadcast --verify -vvvv
```

#### Deploy to Ethereum Mainnet

```bash
forge script script/DeployGassyStation.s.sol:DeployGassyStation --rpc-url ethereum --broadcast --verify -vvvv
```

## Expected Costs

### Base Network
- **Deployment**: ~10,000 gas ≈ $0.003 (at 0.1 gwei)
- **Verification**: Free

### Ethereum Mainnet
- **Deployment**: ~10,000 gas ≈ $0.30 (at 30 gwei)
- **Verification**: Free

## Post-Deployment

1. **Save contract addresses** from the deployment output
2. **Verify on block explorers**:
   - Base: https://basescan.org
   - Ethereum: https://etherscan.io
3. **Update your frontend** with the new contract addresses

## Contract Usage

Once deployed, users can:

1. **Create Gassy contracts**:
   ```solidity
   address gassyAddress = gassyStation.createGassy(paymasterAddress);
   ```

2. **Initialize via 7702**:
   ```solidity
   // User calls 7702 to set their account code to the Gassy contract
   ```

3. **Execute transactions**:
   ```solidity
   // User calls execute() on their account (now running Gassy code)
   ```

## Troubleshooting

### Common Issues

1. **"Private key not set"**: Make sure your `.env` file is properly configured
2. **"Insufficient funds"**: Ensure your deployer account has enough ETH
3. **"Verification failed"**: Check that your API keys are correct and have sufficient quota

### Getting Help

If you encounter issues:
1. Check the deployment logs for error messages
2. Verify your environment variables
3. Ensure you have sufficient ETH for gas fees

## Security Notes

- **Never commit your `.env` file** to version control
- **Use a dedicated deployment wallet** with minimal funds
- **Test on testnets first** before mainnet deployment
