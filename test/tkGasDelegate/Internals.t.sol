pragma solidity ^0.8.30;

import {MockDelegate} from "../mocks/MockDelegate.t.sol";
import {TKGasDelegateTestBase as TKGasDelegateBase} from "./TKGasDelegateTestBase.t.sol";
import {ITKGasDelegate} from "../../src/TKGasStation/interfaces/ITKGasDelegate.sol";

contract InternalsTest is TKGasDelegateBase {
    function test_consumeNonce() public {
        uint128 nonce = 10;
        MockDelegate(user).spoof_Nonce(nonce);
        (uint128 sessionCounter, uint128 n) = MockDelegate(user).state();
        assertEq(n, nonce);
        MockDelegate(user).external_consumeNonce(abi.encodePacked(nonce));
        (uint128 newSessionCounter, uint128 currentNonce) = MockDelegate(user).state();
        assertEq(currentNonce, nonce + 1);
    }

    function test_consumeCounter() public {
        uint128 counter = 10;
        MockDelegate(user).spoof_Counter(counter);
        (uint128 c, uint128 nonce) = MockDelegate(user).state();
        assertEq(c, counter);
        MockDelegate(user).external_requireCounter(abi.encodePacked(counter));
        (uint128 currentCounter, uint128 newNonce) = MockDelegate(user).state();
        assertEq(currentCounter, counter); // counter does not increment
    }
}
