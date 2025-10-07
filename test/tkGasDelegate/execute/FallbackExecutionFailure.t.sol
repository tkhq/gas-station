// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {MockDelegate} from "../../mocks/MockDelegate.t.sol";
import {TKGasDelegateTestBase as TKGasDelegateBase} from "../TKGasDelegateTestBase.t.sol";
import {TKGasDelegate} from "../../../src/TKGasStation/TKGasDelegate.sol";

contract FallbackExecutionFailureTest is TKGasDelegateBase {


    function testFallbackUnexpectedExecutionMode() public {
        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory signature = _signExecute(USER_PRIVATE_KEY, user, nonce, address(0), 0, bytes(""));

        bytes memory fallbackData = _constructFallbackCalldata(bytes1(0xFF), signature, nonce, bytes(""));

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        (success, result) = user.call(fallbackData);
        vm.stopPrank();

        assertEq(success, false);
        assertEq(result, abi.encodeWithSelector(TKGasDelegate.UnsupportedExecutionMode.selector));
    }
}
