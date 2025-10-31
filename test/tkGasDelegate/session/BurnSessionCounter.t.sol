// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {MockDelegate} from "../../mocks/MockDelegate.t.sol";
import {TKGasDelegateTestBase as TKGasDelegateBase} from "../TKGasDelegateTestBase.t.sol";
import {TKGasDelegate} from "../../../src/TKGasStation/TKGasDelegate.sol";

contract BurnSessionCounterTest is TKGasDelegateBase {
    function testBurnSessionCounterWithSignature_Succeeds() public {
        uint128 counter = 1;
        address sender = paymaster;

        // Check counter is not expired initially
        assertFalse(MockDelegate(user).checkSessionCounterExpired(counter));

        // Sign the burn session counter message
        bytes memory signature = _signBurnSessionCounter(USER_PRIVATE_KEY, user, counter, sender);

        // Burn the counter with signature
        vm.prank(paymaster);
        MockDelegate(user).burnSessionCounter(signature, counter, sender);
        vm.stopPrank();

        // Verify the counter is now expired
        assertTrue(MockDelegate(user).checkSessionCounterExpired(counter));
    }

    function testBurnSessionCounterWithSignature_HighCounter_Succeeds() public {
        uint128 counter = type(uint128).max - 7;
        address sender = paymaster;

        // Check counter is not expired initially
        assertFalse(MockDelegate(user).checkSessionCounterExpired(counter));

        // Sign the burn session counter message
        bytes memory signature = _signBurnSessionCounter(USER_PRIVATE_KEY, user, counter, sender);

        // Burn the counter with signature
        vm.prank(paymaster);
        MockDelegate(user).burnSessionCounter(signature, counter, sender);
        vm.stopPrank();

        // Verify the counter is now expired
        assertTrue(MockDelegate(user).checkSessionCounterExpired(counter));
    }

    function testBurnSessionCounterWithSignature_WrongSenderParameter_StillSucceeds() public {
        uint128 counter = 1;
        address sigSender = paymaster;
        address actualCaller = makeAddr("actualCaller");

        // Sign the burn session counter message for sigSender
        // Note: The _sender parameter is part of the signature but msg.sender is not checked
        bytes memory signature = _signBurnSessionCounter(USER_PRIVATE_KEY, user, counter, sigSender);

        // Anyone can call with a valid signature, msg.sender doesn't need to match _sender
        vm.prank(actualCaller);
        MockDelegate(user).burnSessionCounter(signature, counter, sigSender);
        vm.stopPrank();

        // Verify the counter is now expired
        assertTrue(MockDelegate(user).checkSessionCounterExpired(counter));
    }

    function testBurnSessionCounterWithSignature_InvalidSignature_Reverts() public {
        uint128 counter = 1;
        address sender = paymaster;

        // Sign with wrong private key
        bytes memory signature = _signBurnSessionCounter(USER_PRIVATE_KEY_2, user, counter, sender);

        // Attempt to burn with invalid signature
        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.NotSelf.selector);
        MockDelegate(user).burnSessionCounter(signature, counter, sender);
        vm.stopPrank();

        // Verify the counter is still not expired
        assertFalse(MockDelegate(user).checkSessionCounterExpired(counter));
    }

    function testBurnSessionCounterWithSignature_AlreadyBurned_Reverts() public {
        uint128 counter = 1;
        address sender = paymaster;

        // Sign the burn session counter message
        bytes memory signature = _signBurnSessionCounter(USER_PRIVATE_KEY, user, counter, sender);

        // Burn the counter first time
        vm.prank(paymaster);
        MockDelegate(user).burnSessionCounter(signature, counter, sender);
        vm.stopPrank();

        // Verify it's expired
        assertTrue(MockDelegate(user).checkSessionCounterExpired(counter));

        // Try to burn again with same signature - should revert (counter already burned)
        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.InvalidCounter.selector);
        MockDelegate(user).burnSessionCounter(signature, counter, sender);
        vm.stopPrank();

        // Verify it's still expired
        assertTrue(MockDelegate(user).checkSessionCounterExpired(counter));
    }

    function testBurnSessionCounterDirect_Succeeds() public {
        uint128 counter = 1;

        // Check counter is not expired initially
        assertFalse(MockDelegate(user).checkSessionCounterExpired(counter));

        // Burn the counter directly (msg.sender must be self)
        vm.prank(user, user);
        MockDelegate(user).burnSessionCounter(counter);
        vm.stopPrank();

        // Verify the counter is now expired
        assertTrue(MockDelegate(user).checkSessionCounterExpired(counter));
    }

    function testBurnSessionCounterDirect_NotSelf_Reverts() public {
        uint128 counter = 1;

        // Attempt to burn directly but not as self
        vm.prank(user); // origin != user
        vm.expectRevert();
        MockDelegate(user).burnSessionCounter(counter);
        vm.stopPrank();

        // Verify the counter is still not expired
        assertFalse(MockDelegate(user).checkSessionCounterExpired(counter));
    }

    function testBurnSessionCounterThenExecute_Reverts() public {
        mockToken.mint(user, 100 ether);
        address receiver = makeAddr("receiver");

        uint128 counter = 1;
        address sender = paymaster;

        // Burn the counter
        bytes memory burnSignature = _signBurnSessionCounter(USER_PRIVATE_KEY, user, counter, sender);
        vm.prank(paymaster);
        MockDelegate(user).burnSessionCounter(burnSignature, counter, sender);
        vm.stopPrank();

        // Verify it's expired
        assertTrue(MockDelegate(user).checkSessionCounterExpired(counter));

        // Try to execute with the burned counter
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));

        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 5 * 10 ** 18);
        bytes memory data = _constructSessionExecuteBytes(signature, counter, deadline, address(mockToken), 0, args);

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.InvalidCounter.selector);
        MockDelegate(user).executeSession(data);
        vm.stopPrank();

        // Verify the transaction did not go through
        assertEq(mockToken.balanceOf(receiver), 0);
    }
}
