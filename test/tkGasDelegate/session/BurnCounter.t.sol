// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {MockDelegate} from "../../mocks/MockDelegate.t.sol";
import {TKGasDelegateTestBase as TKGasDelegateBase} from "../TKGasDelegateTestBase.t.sol";

contract BurnSessionTest is TKGasDelegateBase {
    function testBurnSessionCounter() public {
        uint128 counter = 0;
        bytes memory signature = _signBurnSessionCounter(USER_PRIVATE_KEY, user, counter, paymaster);
        vm.startPrank(paymaster);
        MockDelegate(user).burnSessionCounter(signature, counter, paymaster);
        vm.stopPrank();
        (uint128 sessionCounter1,) = MockDelegate(user).state();
        assertEq(sessionCounter1, 1);
    }

    function testDirectBurnSessionCounter() public {
        vm.startPrank(user, user);
        MockDelegate(user).burnSessionCounter();
        vm.stopPrank();
        (uint128 sessionCounter1a,) = MockDelegate(user).state();
        assertEq(sessionCounter1a, 1);
        vm.startPrank(user, user);
        MockDelegate(user).burnSessionCounter();
        vm.stopPrank();
        (uint128 sessionCounter2,) = MockDelegate(user).state();
        assertEq(sessionCounter2, 2);

        vm.startPrank(user); // not tx origin
        vm.expectRevert();
        MockDelegate(user).burnSessionCounter();
        vm.stopPrank();
    }

    function testGassyBurnHighSessionCounter() public {
        uint128 counter = type(uint128).max - 7;

        MockDelegate(user).spoof_Counter(counter);

        bytes memory signature = _signBurnSessionCounter(USER_PRIVATE_KEY, user, counter, paymaster);

        vm.prank(paymaster);
        MockDelegate(user).burnSessionCounter(signature, counter, paymaster);
        vm.stopPrank();

        (uint128 currentCounter,) = MockDelegate(user).state();
        assertEq(currentCounter, counter + 1);
    }

    function testBurnSessionCounterUncheckedWillWrapAround() public {
        uint128 counter = type(uint128).max;

        MockDelegate(user).spoof_Counter(counter);

        bytes memory signature = _signBurnSessionCounter(USER_PRIVATE_KEY, user, counter, paymaster);

        vm.prank(paymaster);
        MockDelegate(user).burnSessionCounter(signature, counter, paymaster);
        vm.stopPrank();

        (uint128 currentCounter,) = MockDelegate(user).state();
        assertEq(currentCounter, 0);
    }
}
