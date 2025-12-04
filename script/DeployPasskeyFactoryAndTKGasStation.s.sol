// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "forge-std/console2.sol";

import {PasskeyFactory} from "../src/TKGasStation/PasskeyWallets/PasskeyFactory.sol";
import {PasskeyGasStation} from "../src/TKGasStation/PasskeyWallets/PasskeyGasStation.sol";
import {TKGasStation} from "../src/TKGasStation/TKGasStation.sol";

/// @notice Deploys PasskeyFactory and a TKGasStation wired to its implementation, on Base or any configured chain.
contract DeployPasskeyFactoryAndTKGasStation is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        // Deploy the PasskeyFactory.
        PasskeyFactory passkeyFactory = new PasskeyFactory();
        console2.log("PasskeyFactory deployed at:", address(passkeyFactory));

        // The PasskeyFactory's IMPLEMENTATION is the delegate implementation (PasskeyDelegate).
        address delegateImplementation = passkeyFactory.IMPLEMENTATION();
        console2.log("Passkey delegate implementation at:", delegateImplementation);

        // Deploy TKGasStation pointing at the delegate implementation.
        PasskeyGasStation tkGasStation = new PasskeyGasStation(delegateImplementation);
        console2.log("TKGasStation deployed at:", address(tkGasStation));

        vm.stopBroadcast();
    }
}


