// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "forge-std/console2.sol";
import {TKGasDelegate} from "../src/TKGasStation/TKGasDelegate.sol";

contract VerifyDeployAddress is Script {
    address private constant IMMUTABLE_CREATE2_FACTORY = 0x0000000000FFe8B47B3e2130213B802212439497;
    address private constant EXPECTED_ADDRESS = 0xCcd07F0e6Ffd4B33F181cd5E1674e35cc674065E;

    function run() external {
        bytes32 _salt = 0x0000000000000000000000000000000000000000000000000000004761737379; // "Gassy"

        // Get the creation code (TKGasDelegate has no constructor args)
        bytes memory _initCode = type(TKGasDelegate).creationCode;

        // Compute CREATE2 address
        bytes32 initCodeHash = keccak256(_initCode);
        bytes32 hash = keccak256(abi.encodePacked(bytes1(0xff), IMMUTABLE_CREATE2_FACTORY, _salt, initCodeHash));

        address computedAddress = address(uint160(uint256(hash)));

        console2.log("Expected address:", EXPECTED_ADDRESS);
        console2.log("Computed address:", computedAddress);
        console2.log("Init code hash:", vm.toString(initCodeHash));

        if (computedAddress == EXPECTED_ADDRESS) {
            console2.log("\n[SUCCESS] Addresses match! Deployment will be at the same address.");
        } else {
            console2.log("\n[ERROR] Addresses do NOT match! Bytecode has changed.");
        }
    }
}
