// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {MockDelegate} from "../../mocks/MockDelegate.t.sol";
import {TKGasDelegateTestBase as TKGasDelegateBase} from "../TKGasDelegateTestBase.t.sol";

contract BurnTest is TKGasDelegateBase {
    function testGassyBurnNonce() public {
        uint128 nonce = MockDelegate(user).nonce();

        bytes memory signature = _signBurnNonce(USER_PRIVATE_KEY, user, nonce);

        vm.prank(paymaster);
        MockDelegate(user).burnNonce(signature, nonce);
        vm.stopPrank();

        uint128 currentNonce = MockDelegate(user).nonce();
        assertEq(currentNonce, nonce + 1);
    }

    function testGassyBurnHighNonce() public {
        uint128 nonce = type(uint128).max - 7;
        uint64 prefix = uint64(nonce >> 64);

        MockDelegate(user).spoof_Nonce(nonce);

        bytes memory signature = _signBurnNonce(USER_PRIVATE_KEY, user, nonce);

        vm.prank(paymaster);
        MockDelegate(user).burnNonce(signature, nonce);
        vm.stopPrank();

        uint128 currentNonce = MockDelegate(user).getNonce(prefix);
        assertEq(currentNonce, nonce + 1);
    }

    function testBurnNonceUncheckedWillWrapAround() public {
        // since nonces can only be incremente once per transaction, and it takes up to 128 bits to overflow, there is no check
        // This lack of check is acceptable since it's a state that can only be increased by one per transaction and it would take aeons to overflow
        uint128 nonce = type(uint128).max;

        MockDelegate(user).spoof_Nonce(nonce);

        bytes memory signature = _signBurnNonce(USER_PRIVATE_KEY, user, nonce);

        vm.prank(paymaster);
        MockDelegate(user).burnNonce(signature, nonce);
        vm.stopPrank();

        uint128 currentNonce = MockDelegate(user).nonce();
        assertEq(currentNonce, 0);
    }

    function testGassyBurnNonceRevertsInvalidNonce() public {
        uint128 nonce = MockDelegate(user).nonce();

        bytes memory signature = _signBurnNonce(USER_PRIVATE_KEY, user, nonce + 1);

        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).burnNonce(signature, nonce + 1);
        vm.stopPrank();

        uint128 currentNonce = MockDelegate(user).nonce();
        assertEq(currentNonce, nonce);
    }

    function testGassyBurnNonceThenExecute() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        uint128 nonce = MockDelegate(user).nonce();

        bytes memory burnSignature = _signBurnNonce(USER_PRIVATE_KEY, user, nonce);

        vm.prank(paymaster);
        MockDelegate(user).burnNonce(burnSignature, nonce);
        vm.stopPrank();

        uint128 currentNonce = MockDelegate(user).nonce();
        assertEq(currentNonce, nonce + 1);

        bytes memory executeSignature = _signExecute(
            USER_PRIVATE_KEY,
            user,
            nonce,
            uint32(block.timestamp + 86400),
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
        );

        bytes memory result;
        vm.prank(paymaster);
        vm.expectRevert();
        bytes memory execData = _constructExecuteBytes(
            executeSignature,
            nonce,
            uint32(block.timestamp + 86400),
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
        );
        result = MockDelegate(user).executeReturns(execData);
        vm.stopPrank();

        assertEq(mockToken.balanceOf(receiver), 0);
    }

    function testGassyDirectBurnNonce() public {
        uint128 nonce = MockDelegate(user).nonce();

        vm.startPrank(user, user);
        MockDelegate(user).burnNonce(0);
        vm.stopPrank();

        uint128 currentNonce = MockDelegate(user).nonce();
        assertEq(currentNonce, nonce + 1);

        vm.startPrank(user);
        vm.expectRevert();
        MockDelegate(user).burnNonce(0);
        vm.stopPrank();
    }

    function testGassyDirectBurnNonceRevertsInvalidNonce() public {
        uint128 nonce = MockDelegate(user).nonce();

        vm.startPrank(user, user);
        MockDelegate(user).burnNonce(0);
        vm.stopPrank();

        uint128 currentNonce = MockDelegate(user).nonce();
        assertEq(currentNonce, nonce + 1);

        vm.startPrank(user);
        vm.expectRevert();
        MockDelegate(user).burnNonce(0);
        vm.stopPrank();
    }

    function testGassyDirectBurnNonceThenExecute() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        uint128 nonce = MockDelegate(user).nonce();

        vm.startPrank(user, user);
        MockDelegate(user).burnNonce(0);
        vm.stopPrank();

        uint128 currentNonce = MockDelegate(user).nonce();
        assertEq(currentNonce, nonce + 1);

        bytes memory executeSignature = _signExecute(
            USER_PRIVATE_KEY,
            payable(address(tkGasDelegate)),
            nonce,
            uint32(block.timestamp + 86400),
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
        );

        bytes memory result;
        vm.prank(paymaster);
        vm.expectRevert();
        bytes memory execData2 = _constructExecuteBytes(
            executeSignature,
            nonce,
            uint32(block.timestamp + 86400),
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
        );
        result = MockDelegate(user).executeReturns(execData2);
        vm.stopPrank();

        assertEq(mockToken.balanceOf(receiver), 0);
    }

    function testGassyDirectBurnNonceVsSignatureBurn() public {
        uint128 nonce = MockDelegate(user).nonce();

        vm.startPrank(user, user);
        MockDelegate(user).burnNonce(0);
        vm.stopPrank();

        uint128 nonceAfterDirect = MockDelegate(user).nonce();
        assertEq(nonceAfterDirect, nonce + 1);

        uint128 newNonce = MockDelegate(user).nonce();
        bytes memory signature = _signBurnNonce(USER_PRIVATE_KEY, user, newNonce);

        vm.prank(paymaster);
        MockDelegate(user).burnNonce(signature, newNonce);
        vm.stopPrank();

        uint128 nonceAfterSignature = MockDelegate(user).nonce();
        assertEq(nonceAfterSignature, newNonce + 1);

        assertEq(nonceAfterSignature, nonceAfterDirect + 1);
    }

    function testBurnNonceWithDifferentPrefixes() public {
        // Set up nonces for prefix 0 and prefix 1
        uint128 noncePrefix0 = 5; // prefix 0, nonce value 5
        uint128 noncePrefix1 = (uint128(1) << 64) | 10; // prefix 1, nonce value 10

        // Set the nonces
        MockDelegate(user).spoof_Nonce(noncePrefix0);
        MockDelegate(user).spoof_Nonce(noncePrefix1);

        // Verify initial nonces
        uint128 initialNonce0 = MockDelegate(user).getNonce(0);
        uint128 initialNonce1 = MockDelegate(user).getNonce(1);
        assertEq(initialNonce0, noncePrefix0);
        assertEq(initialNonce1, noncePrefix1);

        // Burn nonce at prefix 0
        vm.startPrank(user, user);
        MockDelegate(user).burnNonce(0);
        vm.stopPrank();

        // Verify prefix 0 was incremented, prefix 1 unchanged
        uint128 nonce0AfterBurn = MockDelegate(user).getNonce(0);
        uint128 nonce1AfterFirstBurn = MockDelegate(user).getNonce(1);
        assertEq(nonce0AfterBurn, noncePrefix0 + 1);
        assertEq(nonce1AfterFirstBurn, noncePrefix1); // Should be unchanged

        // Burn nonce at prefix 1
        vm.startPrank(user, user);
        MockDelegate(user).burnNonce(1);
        vm.stopPrank();

        // Verify both prefixes were incremented correctly
        uint128 nonce0AfterBothBurns = MockDelegate(user).getNonce(0);
        uint128 nonce1AfterBothBurns = MockDelegate(user).getNonce(1);
        assertEq(nonce0AfterBothBurns, noncePrefix0 + 1); // Still +1 from first burn
        assertEq(nonce1AfterBothBurns, noncePrefix1 + 1); // Now +1 from second burn
    }

    function testBurnNonceParameterless() public {
        uint128 nonce = MockDelegate(user).nonce();

        // Must be called by tx.origin (user, user)
        vm.startPrank(user, user);
        MockDelegate(user).burnNonce();
        vm.stopPrank();

        uint128 currentNonce = MockDelegate(user).nonce();
        assertEq(currentNonce, nonce + 1);
    }

    function testBurnNonceParameterlessRevertsIfNotSelf() public {
        uint128 nonce = MockDelegate(user).nonce();

        // Should revert if not called by self or tx.origin
        vm.startPrank(paymaster);
        vm.expectRevert();
        MockDelegate(user).burnNonce();
        vm.stopPrank();

        // Nonce should be unchanged
        uint128 currentNonce = MockDelegate(user).nonce();
        assertEq(currentNonce, nonce);
    }

    function testBurnNonceParameterlessMultipleTimes() public {
        uint128 nonce = MockDelegate(user).nonce();

        // Burn nonce multiple times
        vm.startPrank(user, user);
        MockDelegate(user).burnNonce();
        uint128 nonce1 = MockDelegate(user).nonce();
        assertEq(nonce1, nonce + 1);

        MockDelegate(user).burnNonce();
        uint128 nonce2 = MockDelegate(user).nonce();
        assertEq(nonce2, nonce + 2);

        MockDelegate(user).burnNonce();
        uint128 nonce3 = MockDelegate(user).nonce();
        assertEq(nonce3, nonce + 3);
        vm.stopPrank();
    }
}
