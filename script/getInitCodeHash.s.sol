// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "forge-std/console2.sol";
import {TKGasStation} from "../src/TKGasStation/TKGasStation.sol";

contract GetInitCodeHash is Script {
    function run() external {
        address _delegate = vm.envAddress("DELEGATE_ADDRESS");

        // Get the creation code
        bytes memory _creationCode = type(TKGasStation).creationCode;

        // Encode the constructor argument
        bytes memory _constructorArgs = abi.encode(_delegate);

        // Concatenate creation code with constructor args
        bytes memory _initCode = abi.encodePacked(_creationCode, _constructorArgs);

        // Hash the init code
        bytes32 _initCodeHash = keccak256(_initCode);

        console2.log("Creation code length:", _creationCode.length);
        console2.log("Init code hash (keccak256):");
        console2.logBytes32(_initCodeHash);
        console2.log("\nFor create2crunch, use:");
        console2.log("INIT_CODE_HASH=", vm.toString(_initCodeHash));
    }
}
