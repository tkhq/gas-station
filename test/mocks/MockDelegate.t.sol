// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {TKGasDelegate} from "../../src/TKGasStation/TKGasDelegate.sol";
import {IBatchExecution} from "../../src/TKGasStation/interfaces/IBatchExecution.sol";

contract MockDelegate is TKGasDelegate {
    constructor() TKGasDelegate() {}

    function spoof_Nonce(uint128 _nonce) external {
        uint64 prefix = uint64(_nonce >> 64);
        uint64 noncePart = uint64(_nonce);
        _getStateStorage().nonce[prefix] = noncePart;
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

    function external_DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparator();
    }

    function external_hashCallArrayUnchecked(IBatchExecution.Call[] calldata _calls) external pure returns (bytes32) {
        return _hashCallArrayUnchecked(_calls);
    }
}
