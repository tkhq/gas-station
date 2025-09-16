// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "../src/TKGasStation/TKGasStation.sol";

/*
contract DeployTKGasStation is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        
        console.log("Deploying TKGasStation with the account:", deployer);
        console.log("Account balance:", deployer.balance);
        
        vm.startBroadcast(deployerPrivateKey);
        
        // Deploy TKGasStation
        TKGasStation gasStation = new TKGasStation();
        
        console.log("TKGasStation deployed at:", address(gasStation));
        
        vm.stopBroadcast();
        
        // Verify contract
        console.log("Contract deployed successfully!");
        console.log("TKGasStation address:", address(gasStation));
    }
}
*/
