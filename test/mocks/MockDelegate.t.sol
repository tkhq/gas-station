// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {TKGasDelegate} from "../../src/TKGasStation/TKGasDelegate.sol";

contract MockDelegate is TKGasDelegate {
    constructor() TKGasDelegate() {}

    function spoof_Nonce(uint128 _nonce) external {
        _getStateStorage().nonce = _nonce;
    }

    function spoof_burnSessionCounter(uint128 _counter) external {
        _getStateStorage().expiredSessionCounters[bytes16(_counter)] = true;
    }

    function external_consumeNonce(bytes calldata _nonceBytes) external {
        _consumeNonce(_nonceBytes);
    }

    function external_requireCounter(bytes calldata _counterBytes) external view {
        _requireCounter(_counterBytes);
    }

    function external_EXECUTION_TYPEHASH() external pure returns (bytes32) {
        return EXECUTION_TYPEHASH;
    }

    function external_APPROVE_THEN_EXECUTE_TYPEHASH() external pure returns (bytes32) {
        return APPROVE_THEN_EXECUTE_TYPEHASH;
    }

    function external_BATCH_EXECUTION_TYPEHASH() external pure returns (bytes32) {
        return BATCH_EXECUTION_TYPEHASH;
    }

    function external_CALL_TYPEHASH() external pure returns (bytes32) {
        return CALL_TYPEHASH;
    }

    function external_BURN_NONCE_TYPEHASH() external pure returns (bytes32) {
        return BURN_NONCE_TYPEHASH;
    }

    function external_SESSION_EXECUTION_TYPEHASH() external pure returns (bytes32) {
        return SESSION_EXECUTION_TYPEHASH;
    }

    function external_ARBITRARY_SESSION_EXECUTION_TYPEHASH() external pure returns (bytes32) {
        return ARBITRARY_SESSION_EXECUTION_TYPEHASH;
    }

    function external_BURN_SESSION_COUNTER_TYPEHASH() external pure returns (bytes32) {
        return BURN_SESSION_COUNTER_TYPEHASH;
    }
}
