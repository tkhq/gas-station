// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {TKGasDelegate} from "../../src/TKGasStation/TKGasDelegate.sol";

contract MockDelegate is TKGasDelegate {
    constructor() TKGasDelegate() {}

    function spoof_Nonce(uint128 _nonce) external {
        state.nonce = _nonce;
    }

    function spoof_Counter(uint128 _counter) external {
        state.sessionCounter = _counter;
    }
}
