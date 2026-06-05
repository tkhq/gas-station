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
        // since nonces can only be incremented once per transaction, and it takes up to 128 bits to overflow, there is no check
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

        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).execute(
            _constructExecuteBytes(
                executeSignature,
                nonce,
                uint32(block.timestamp + 86400),
                address(mockToken),
                0,
                abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
            )
        );
        vm.stopPrank();

        assertEq(mockToken.balanceOf(receiver), 0);
    }

}
