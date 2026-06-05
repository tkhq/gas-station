// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {TKGasDelegate} from "../../src/TKGasStation/TKGasDelegate.sol";
import {IBatchExecution} from "../../src/TKGasStation/interfaces/IBatchExecution.sol";

contract MockDelegate is TKGasDelegate {
    constructor(address _gasStation) TKGasDelegate(_gasStation) {}

    function spoof_Nonce(uint128 _nonce) external {
        _getStateStorage().nonce = _nonce;
    }

    function external_consumeNonce(bytes calldata _nonceBytes) external {
        _consumeNonce(_nonceBytes);
    }

    function external_EXECUTION_TYPEHASH() external pure returns (bytes32) {
        return EXECUTION_TYPEHASH;
    }

    function external_BATCH_EXECUTION_TYPEHASH() external pure returns (bytes32) {
        return BATCH_EXECUTION_TYPEHASH;
    }

    function external_CALL_TYPEHASH() external pure returns (bytes32) {
        return CALL_TYPEHASH;
    }

    function external_DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparator();
    }

    function external_hashCallArrayUnchecked(IBatchExecution.Call[] calldata _calls) external pure returns (bytes32) {
        return _hashCallArrayUnchecked(_calls);
    }

    function external_BURN_NONCE_TYPEHASH() external pure returns (bytes32) {
        return BURN_NONCE_TYPEHASH;
    }
}
