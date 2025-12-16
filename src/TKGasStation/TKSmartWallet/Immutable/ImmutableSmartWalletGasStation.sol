// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {TKGasStation} from "../../TKGasStation.sol";

import {IsDelegated} from "../../IsDelegated.sol";

contract ImmutableSmartWalletGasStation is TKGasStation {

    // constants for the minimal proxy pattern by solady LibClone
    uint256 private immutable EXPECTED_RUNTIME_CODE_SIZE; // 44 bytes if nothing
    bytes10 private constant EXPECTED_PREFIX = 0x363d3d373d3d3d363d73;
    bytes15 private constant EXPECTED_SUFFIX = 0x5af43d82803e903d91602b57fd5bf3;

    constructor(address _tkGasDelegate, uint256 _expectedRuntimeCodeSize) TKGasStation(_tkGasDelegate) {
        EXPECTED_RUNTIME_CODE_SIZE = _expectedRuntimeCodeSize;
    }

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