// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "forge-std/console2.sol";

import {TKSmartWalletFactory} from "../src/TKGasStation/TKSmartWallet/TKSmartWalletFactory.sol";
import {TKSmartWalletGasStation} from "../src/TKGasStation/TKSmartWallet/TKSmartWalletGasStation.sol";
import {TKGasStation} from "../src/TKGasStation/TKGasStation.sol";

/// @notice Deploys TKSmartWalletFactory and a TKGasStation wired to its implementation, on Base or any configured chain.
contract DeployPasskeyFactoryAndTKGasStation is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        // Deploy the TKSmartWalletFactory.
        TKSmartWalletFactory tkSmartWalletFactory = new TKSmartWalletFactory();
        console2.log("TKSmartWalletFactory deployed at:", address(tkSmartWalletFactory));

        // The TKSmartWalletFactory's IMPLEMENTATION is the delegate implementation (TKSmartWalletDelegate).
        address delegateImplementation = tkSmartWalletFactory.IMPLEMENTATION();
        console2.log("TKSmartWallet delegate implementation at:", delegateImplementation);

        // Deploy TKGasStation pointing at the delegate implementation.
        TKSmartWalletGasStation tkGasStation = new TKSmartWalletGasStation(delegateImplementation);
        console2.log("TKGasStation deployed at:", address(tkGasStation));

        vm.stopBroadcast();
    }
}


