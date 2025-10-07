// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {TKGasDelegate} from "../../../src/TKGasStation/TKGasDelegate.sol";
import {MockDelegate} from "../../mocks/MockDelegate.t.sol";
import {MockERC20} from "../../mocks/MockERC20.t.sol";
import {TKGasDelegateTestBase} from "../TKGasDelegateTestBase.t.sol";

contract NonceDecodingConsistencyTest is TKGasDelegateTestBase {
    function testNonceDecodingConsistency() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        (, uint128 nonce) = MockDelegate(user).state();

        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);

        bytes memory signature = _signExecute(USER_PRIVATE_KEY, user, nonce, address(mockToken), 0, args);

        bytes memory executeData = _constructExecuteBytes(signature, nonce, address(mockToken), 0, args);

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        (success, result) = MockDelegate(user).execute(executeData);

        assertTrue(success, "Execute should succeed with consistent nonce decoding");

        assertEq(mockToken.balanceOf(receiver), 10 * 10 ** 18);
    }

    function testNonceDecodingInconsistencyWouldFail() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        (, uint128 nonce) = MockDelegate(user).state();

        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);

        bytes32 wrongHash = keccak256("wrong hash that will never match");

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_PRIVATE_KEY, wrongHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes memory executeData = _constructExecuteBytes(signature, nonce, address(mockToken), 0, args);

        vm.prank(paymaster);
        vm.expectRevert(abi.encodeWithSelector(TKGasDelegate.NotSelf.selector));
        MockDelegate(user).execute(executeData);

        assertEq(mockToken.balanceOf(receiver), 0);
    }
}
