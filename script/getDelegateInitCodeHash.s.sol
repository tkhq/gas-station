// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "forge-std/console2.sol";
import {TKGasDelegate} from "../src/TKGasStation/TKGasDelegate.sol";

contract GetDelegateInitCodeHash is Script {
    function run() external {
        // Get the creation code (TKGasDelegate has no constructor args)
        bytes memory _initCode = type(TKGasDelegate).creationCode;

        // Hash the init code
        bytes32 _initCodeHash = keccak256(_initCode);

        console2.log("Init code hash (keccak256):");
        console2.logBytes32(_initCodeHash);
        console2.log("\nFor create2crunch, use:");
        console2.log("INIT_CODE_HASH=", vm.toString(_initCodeHash));
    }
}
