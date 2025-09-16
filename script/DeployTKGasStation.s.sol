// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "../src/TKGasStation/TKGasStation.sol";

contract DeployTKGasStation is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        
        vm.startBroadcast(deployerPrivateKey);
        bytes32 salt = keccak256(abi.encodePacked("TKGasStation V1")); // all chains will have the same salt 

        TKGasStation gasStation = new TKGasStation{salt: salt}();
        
        console.log("TKGasStation at:", address(gasStation));
        
        vm.stopBroadcast();
        
        console.log("TKGasStation address:", address(gasStation));
    }
}
