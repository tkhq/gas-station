// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ITKGasDelegate} from "../../src/TKGasStation/interfaces/ITKGasDelegate.sol";

contract MockReentry {
    function reenter(address target, bytes calldata data) external returns (bytes memory) {
        (bool success, bytes memory result) = target.call(data);
        success; // silence unused
        return result;
    }
}
