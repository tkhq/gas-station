// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {TKGasStation} from "../TKGasStation.sol";

import {IsDelegated} from "../IsDelegated.sol";

contract ImmutableSmartWalletGasStation is TKGasStation {

    // constants for the minimal proxy pattern by solady LibClone
    uint256 private constant EXPECTED_RUNTIME_CODE_SIZE = 0x2c; // 44 bytes
    bytes11 private constant EXPECTED_PREFIX = 0x3d3d3d3d363d3d37363d73;
    bytes13 private constant EXPECTED_SUFFIX = 0x5af43d3d93803e602a57fd5bf3;

    constructor(address _tkGasDelegate) TKGasStation(_tkGasDelegate) {}

    function _isDelegated(address _targetEoA) internal override view returns (bool) {
        return IsDelegated.isDelegatedMinimalProxy(
            _targetEoA,
            TK_GAS_DELEGATE,
            EXPECTED_RUNTIME_CODE_SIZE,
            EXPECTED_PREFIX,
            EXPECTED_SUFFIX
        );
    }

}