// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "forge-std/console2.sol";
import {TKGasStation} from "../src/TKGasStation/TKGasStation.sol";
import {TKGasDelegate} from "../src/TKGasStation/TKGasDelegate.sol";

contract DeployTKGasStation is Script {
    function run() external {
        uint256 _deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(_deployerPrivateKey);

        // Deploy TKGasDelegate first with deterministic deployment
        TKGasDelegate _delegate = new TKGasDelegate{salt: keccak256("Gassy")}();
        // console2.log("TKGasDelegate deployed at:", address(_delegate));

        // Use existing TKGasDelegate address
        //address _delegate = 0xfA5a20d173801C9762C5DdA2157e0133ed9ca32a;
        //console2.log("Using existing TKGasDelegate at:", _delegate);

        // Deploy TKGasStation with mined salt for 2 null bytes
        TKGasStation _station =
            new TKGasStation{salt: keccak256("Gassy")}(address(_delegate));
        console2.log("TKGasStation deployed at:", address(_station));

        vm.stopBroadcast();
    }
}
