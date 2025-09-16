// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "../src/Gassy/GassyStation.sol";

/*
contract CreateGassy is Script {
    // Deployed GassyStation addresses
    address constant BASE_GASSY_STATION = 0xFb76BED658C3f590084Fa75beaD6AB5513a2Cf3d;
    address constant ETHEREUM_GASSY_STATION = 0x7c614D2ECf3273bb032d00B207cF86810d098F40;
    
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        
        console.log("Creating Gassy contracts with the account:", deployer);
        console.log("Account balance:", deployer.balance);
        
        // Example paymaster address (you can change this)
        address paymaster = address(0x67A5D6C8Cab5fd31aAB30AB6D69101EaB5fE1E27);
        
        vm.startBroadcast(deployerPrivateKey);
        
        // Create Gassy on Base
        console.log("\n=== Creating Gassy on Base ===");
        GassyStation baseStation = GassyStation(BASE_GASSY_STATION);
        address baseGassy = baseStation.createGassy(paymaster);
        console.log("Base Gassy created at:", baseGassy);
        
        // Create Gassy on Ethereum
        console.log("\n=== Creating Gassy on Ethereum ===");
        GassyStation ethereumStation = GassyStation(ETHEREUM_GASSY_STATION);
        address ethereumGassy = ethereumStation.createGassy(paymaster);
        console.log("Ethereum Gassy created at:", ethereumGassy);
        
        vm.stopBroadcast();
        
        console.log("\n=== Summary ===");
        console.log("Base Gassy address:", baseGassy);
        console.log("Ethereum Gassy address:", ethereumGassy);
        console.log("Paymaster address:", paymaster);
    }
    
    // Function to create Gassy on Base only
    function createOnBase(address _paymaster) external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        vm.startBroadcast(deployerPrivateKey);
        
        GassyStation baseStation = GassyStation(BASE_GASSY_STATION);
        address gassy = baseStation.createGassy(_paymaster);
        
        console.log("Gassy created on Base at:", gassy);
        console.log("Paymaster:", _paymaster);
        
        vm.stopBroadcast();
    }
    
    // Function to create Gassy on Ethereum only
    function createOnEthereum(address _paymaster) external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        vm.startBroadcast(deployerPrivateKey);
        
        GassyStation ethereumStation = GassyStation(ETHEREUM_GASSY_STATION);
        address gassy = ethereumStation.createGassy(_paymaster);
        
        console.log("Gassy created on Ethereum at:", gassy);
        console.log("Paymaster:", _paymaster);
        
        vm.stopBroadcast();
    }
}
*/
