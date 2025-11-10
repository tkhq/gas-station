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

        MockDelegate(user).spoof_Nonce(nonce);

        bytes memory signature = _signBurnNonce(USER_PRIVATE_KEY, user, nonce);

        vm.prank(paymaster);
        MockDelegate(user).burnNonce(signature, nonce);
        vm.stopPrank();

        uint128 currentNonce = MockDelegate(user).nonce();
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
        MockDelegate(user).burnNonce();
        vm.stopPrank();

        uint128 currentNonce = MockDelegate(user).nonce();
        assertEq(currentNonce, nonce + 1);

        vm.startPrank(user);
        vm.expectRevert();
        MockDelegate(user).burnNonce();
        vm.stopPrank();
    }

    function testGassyDirectBurnNonceRevertsInvalidNonce() public {
        uint128 nonce = MockDelegate(user).nonce();

        vm.startPrank(user, user);
        MockDelegate(user).burnNonce();
        vm.stopPrank();

        uint128 currentNonce = MockDelegate(user).nonce();
        assertEq(currentNonce, nonce + 1);

        vm.startPrank(user);
        vm.expectRevert();
        MockDelegate(user).burnNonce();
        vm.stopPrank();
    }

    function testGassyDirectBurnNonceThenExecute() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        uint128 nonce = MockDelegate(user).nonce();

        vm.startPrank(user, user);
        MockDelegate(user).burnNonce();
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
        MockDelegate(user).burnNonce();
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
}
