// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "forge-std/console2.sol";
import {TKGasDelegate} from "../src/TKGasStation/TKGasDelegate.sol";

contract DeployTKGasDelegate is Script {
    function run() external {
        uint256 _deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(_deployerPrivateKey);

        // Deploy TKGasDelegate with deterministic deployment
        TKGasDelegate _delegate = new TKGasDelegate{salt: keccak256("Gassy")}();
        console2.log("TKGasDelegate deployed at:", address(_delegate));

        vm.stopBroadcast();
    }
}

