// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {TKGasDelegate} from "../../src/TKGasStation/TKGasDelegate.sol";
import {TKGasDelegateTestBase as TKGasDelegateBase} from "./TKGasDelegateTestBase.sol";

contract BurnTest is TKGasDelegateBase {
    function testGassyBurnNonce() public {
        (, uint128 nonce) = TKGasDelegate(user).state();

        bytes memory signature = _signBurnNonce(USER_PRIVATE_KEY, user, nonce);

        vm.prank(paymaster);
        TKGasDelegate(user).burnNonce(signature, nonce);
        vm.stopPrank();

        (, uint128 currentNonce) = TKGasDelegate(user).state();
        assertEq(currentNonce, nonce + 1);
    }

    function testGassyBurnNonceRevertsInvalidNonce() public {
        (, uint128 nonce) = TKGasDelegate(user).state();

        bytes memory signature = _signBurnNonce(USER_PRIVATE_KEY, user, nonce + 1);

        vm.prank(paymaster);
        vm.expectRevert();
        TKGasDelegate(user).burnNonce(signature, nonce + 1);
        vm.stopPrank();

        (, uint128 currentNonce) = TKGasDelegate(user).state();
        assertEq(currentNonce, nonce);
    }

    function testGassyBurnNonceThenExecute() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        (, uint128 nonce) = TKGasDelegate(user).state();

        bytes memory burnSignature = _signBurnNonce(USER_PRIVATE_KEY, user, nonce);

        vm.prank(paymaster);
        TKGasDelegate(user).burnNonce(burnSignature, nonce);
        vm.stopPrank();

        (, uint128 currentNonce) = TKGasDelegate(user).state();
        assertEq(currentNonce, nonce + 1);

        bytes memory executeSignature = _signExecute(
            USER_PRIVATE_KEY,
            user,
            nonce,
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
        );

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        vm.expectRevert();
        bytes memory execData = _constructExecuteBytes(
            executeSignature,
            nonce,
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
        );
        (success, result) = TKGasDelegate(user).execute(execData);
        vm.stopPrank();

        assertEq(mockToken.balanceOf(receiver), 0);
    }

    function testGassyDirectBurnNonce() public {
        (, uint128 nonce) = TKGasDelegate(user).state();

        vm.startPrank(user, user);
        TKGasDelegate(user).burnNonce();
        vm.stopPrank();

        (, uint128 currentNonce) = TKGasDelegate(user).state();
        assertEq(currentNonce, nonce + 1);
    }

    function testGassyDirectBurnNonceRevertsInvalidNonce() public {
        (, uint128 nonce) = TKGasDelegate(user).state();

        vm.startPrank(user, user);
        TKGasDelegate(user).burnNonce();
        vm.stopPrank();

        (, uint128 currentNonce) = TKGasDelegate(user).state();
        assertEq(currentNonce, nonce + 1);
    }

    function testGassyDirectBurnNonceThenExecute() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        (, uint128 nonce) = TKGasDelegate(user).state();

        vm.startPrank(user, user);
        TKGasDelegate(user).burnNonce();
        vm.stopPrank();

        (, uint128 currentNonce) = TKGasDelegate(user).state();
        assertEq(currentNonce, nonce + 1);

        bytes memory executeSignature = _signExecute(
            USER_PRIVATE_KEY,
            payable(address(tkGasDelegate)),
            nonce,
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
        );

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        vm.expectRevert();
        bytes memory execData2 = _constructExecuteBytes(
            executeSignature,
            nonce,
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
        );
        (success, result) = TKGasDelegate(user).execute(execData2);
        vm.stopPrank();

        assertEq(mockToken.balanceOf(receiver), 0);
    }

    function testGassyDirectBurnNonceVsSignatureBurn() public {
        (, uint128 nonce) = TKGasDelegate(user).state();

        vm.startPrank(user, user);
        TKGasDelegate(user).burnNonce();
        vm.stopPrank();

        (, uint128 nonceAfterDirect) = TKGasDelegate(user).state();
        assertEq(nonceAfterDirect, nonce + 1);

        (, uint128 newNonce) = TKGasDelegate(user).state();
        bytes memory signature = _signBurnNonce(USER_PRIVATE_KEY, user, newNonce);

        vm.prank(paymaster);
        TKGasDelegate(user).burnNonce(signature, newNonce);
        vm.stopPrank();

        (, uint128 nonceAfterSignature) = TKGasDelegate(user).state();
        assertEq(nonceAfterSignature, newNonce + 1);

        assertEq(nonceAfterSignature, nonceAfterDirect + 1);
    }

    function testBurnSessionCounter() public {
        uint128 counter = 0;
        bytes memory signature = _signBurnSessionCounter(USER_PRIVATE_KEY, user, counter, paymaster);
        vm.startPrank(paymaster);
        TKGasDelegate(user).burnSessionCounter(signature, counter, paymaster);
        vm.stopPrank();
        (uint128 sessionCounter1,) = TKGasDelegate(user).state();
        assertEq(sessionCounter1, 1);
    }

    function testDirectBurnSessionCounter() public {
        vm.startPrank(user, user);
        TKGasDelegate(user).burnSessionCounter();
        vm.stopPrank();
        (uint128 sessionCounter1a,) = TKGasDelegate(user).state();
        assertEq(sessionCounter1a, 1);
        vm.startPrank(user, user);
        TKGasDelegate(user).burnSessionCounter();
        vm.stopPrank();
        (uint128 sessionCounter2,) = TKGasDelegate(user).state();
        assertEq(sessionCounter2, 2);
    }
}

