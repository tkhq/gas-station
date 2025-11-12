// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "forge-std/console2.sol";
import {TKGasDelegate} from "../src/TKGasStation/TKGasDelegate.sol";
import {TKGasStation} from "../src/TKGasStation/TKGasStation.sol";

interface IImmutableCreate2Factory {
    function safeCreate2(bytes32 _salt, bytes calldata _initCode) external payable returns (address _deploymentAddress);
}

contract DeployTKGasDelegate is Script {

    function run() external {
        uint256 _deployerPrivateKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        bytes32 salt = bytes32(abi.encodePacked(bytes27(0), "Gassy"));
        
        vm.startBroadcast(_deployerPrivateKey);

        // Deploy TKGasDelegate
        TKGasDelegate delegate = new TKGasDelegate{salt:salt}();
        console2.log("TKGasDelegate deployed at:", address(address(delegate)));

        TKGasStation station = new TKGasStation{salt:salt}(address(delegate));
        console2.log("TKGasStation deployed at:", address(address(station)));

        vm.stopBroadcast();
    }
}
