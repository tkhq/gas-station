// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {TKGasDelegate} from "../../src/TKGasStation/TKGasDelegate.sol";

contract MockDelegate is TKGasDelegate {
    constructor() TKGasDelegate() {}

    function spoof_Nonce(uint128 _nonce) external {
        gasDelegateState.nonce = _nonce;
    }

    function spoof_Counter(uint128 _counter) external {
        gasDelegateState.sessionCounter = _counter;
    }

    function external_consumeNonce(bytes calldata _nonceBytes) external {
        _consumeNonce(_nonceBytes);
    }

    function external_requireCounter(bytes calldata _counterBytes) external {
        _requireCounter(_counterBytes);
    }

}
