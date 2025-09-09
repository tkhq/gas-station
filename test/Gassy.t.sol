// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/Gassy/Gassy.sol";
import "../src/Gassy/GassyStation.sol";

contract GassyTest is Test {
    GassyStation public gassyStation;
    Gassy public gassy;
    
    address public paymaster = makeAddr("paymaster");
    address public targetContract = makeAddr("targetContract");
    
    function setUp() public {
        // Deploy GassyStation
        gassyStation = new GassyStation();
        
        // Create Gassy contract
        gassy = Gassy(gassyStation.createGassy(paymaster));
        
    }
    
    function testGassyStationDeployment() public {
        assertTrue(address(gassyStation) != address(0));
    }
    
    function testGassyCreation() public {
        assertTrue(address(gassy) != address(0));
        assertEq(gassy.paymaster(), paymaster);
    }
    
    
    function testGassyExecute() public {
        // TODO: Add execute function tests
    }
    
}
