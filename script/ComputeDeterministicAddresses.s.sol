// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "forge-std/console2.sol";
import {TKGasDelegate} from "../src/TKGasStation/TKGasDelegate.sol";
import {TKGasStation} from "../src/TKGasStation/TKGasStation.sol";

contract ComputeDeterministicAddresses is Script {
    address private constant IMMUTABLE_CREATE2_FACTORY = 0x0000000000FFe8B47B3e2130213B802212439497;
    bytes32 private constant SALT = 0x0000000000000000000000000000000000000000000000000000004761737379; // "Gassy"

    function run() external view {
        // Delegate init code and hash
        bytes memory delegateInitCode = type(TKGasDelegate).creationCode;
        bytes32 delegateInitCodeHash = keccak256(delegateInitCode);

        // Compute delegate CREATE2 address
        bytes32 delegateHash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                IMMUTABLE_CREATE2_FACTORY,
                SALT,
                delegateInitCodeHash
            )
        );
        address delegateAddress = address(uint160(uint256(delegateHash)));

        // Station init code = creationCode + constructor args (delegateAddress)
        bytes memory stationCreationCode = type(TKGasStation).creationCode;
        bytes memory stationConstructorArgs = abi.encode(delegateAddress);
        bytes memory stationInitCode = abi.encodePacked(stationCreationCode, stationConstructorArgs);
        bytes32 stationInitCodeHash = keccak256(stationInitCode);

        // Compute station CREATE2 address
        bytes32 stationHash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                IMMUTABLE_CREATE2_FACTORY,
                SALT,
                stationInitCodeHash
            )
        );
        address stationAddress = address(uint160(uint256(stationHash)));

        console2.log("Computed deterministic addresses (all networks):");
        console2.log("  TKGasDelegate:", delegateAddress);
        console2.log("  TKGasStation :", stationAddress);
    }
}


