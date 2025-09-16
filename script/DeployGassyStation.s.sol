// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "../src/Gassy/GassyStation.sol";

/*
contract DeployGassyStation is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        
        console.log("Deploying GassyStation with the account:", deployer);
        console.log("Account balance:", deployer.balance);
        
        vm.startBroadcast(deployerPrivateKey);
        
        // Deploy GassyStation
        GassyStation gassyStation = new GassyStation();
        
        console.log("GassyStation deployed at:", address(gassyStation));
        
        vm.stopBroadcast();
        
        // Verify contract
        console.log("Contract deployed successfully!");
        console.log("GassyStation address:", address(gassyStation));
    }
}
*/
