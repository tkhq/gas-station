// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {IBatchExecution} from "../../../src/TKGasStation/interfaces/IBatchExecution.sol";
import {MockDelegate} from "../../mocks/MockDelegate.t.sol";
import {MockERC20} from "../../mocks/MockERC20.t.sol";
import {TKGasDelegateTestBase as TKGasDelegateBase} from "../TKGasDelegateTestBase.t.sol";
import {TKGasDelegate} from "../../../src/TKGasStation/TKGasDelegate.sol";

contract SessionTest is TKGasDelegateBase {
    function testSessionExecute_Succeeds() public {
        mockToken.mint(user, 10 * 10 ** 18);
        address receiver = makeAddr("receiver");

        (uint128 counter,) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));

        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 5 * 10 ** 18);
        bytes memory data = _constructSessionExecuteBytes(signature, counter, deadline, address(mockToken), 0, args);

        vm.prank(paymaster);
        (bool success,) = MockDelegate(user).executeSession(data);
        vm.stopPrank();

        assertTrue(success);
        assertEq(mockToken.balanceOf(receiver), 5 * 10 ** 18);
    }

    function testSessionExecute_ExpiredDeadline_Reverts() public {
        (uint128 counter,) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp - 1);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));
        bytes memory args = bytes("");
        bytes memory data = _constructSessionExecuteBytes(signature, counter, deadline, address(mockToken), 0, args);

        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).executeSession(data);
        vm.stopPrank();
    }

    function testSessionExecute_InvalidCounter_Reverts() public {
        (uint128 counter,) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));
        bytes memory args = bytes("");
        bytes memory data = _constructSessionExecuteBytes(signature, counter, deadline, address(mockToken), 0, args);

        // Burn the counter
        vm.prank(user, user);
        MockDelegate(user).burnSessionCounter();
        vm.stopPrank();

        (uint128 newCounter,) = MockDelegate(user).state();

        assertEq(counter + 1, newCounter);

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.InvalidCounter.selector);
        MockDelegate(user).executeSession(data);
        vm.stopPrank();
    }

    function testSessionExecute_Replayability_AllowsMultipleExecutions() public {
        mockToken.mint(user, 100 ether);
        address receiver = makeAddr("receiver");

        (uint128 counter,) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 5 ether);
        bytes memory data = _constructSessionExecuteBytes(signature, counter, deadline, address(mockToken), 0, args);

        vm.startPrank(paymaster);
        (bool s1,) = MockDelegate(user).executeSession(data);
        (bool s2,) = MockDelegate(user).executeSession(data); // replay with same counter
        vm.stopPrank();

        assertTrue(s1 && s2);
        assertEq(mockToken.balanceOf(receiver), 10 ether);
    }

    function testSessionExecute_AttemptDifferentContract_Reverts() public {
        // build a valid signature for mockToken but attempt to call a different contract
        address other = makeAddr("otherContract");
        (uint128 counter,) = MockDelegate(user).state();
        vm.deal(user, 1 ether);
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));

        // args don't matter, target is wrong
        bytes memory args = bytes("");
        bytes memory data = _constructSessionExecuteBytes(signature, counter, deadline, other, 1 ether, args);

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.NotSelf.selector);
        MockDelegate(user).executeSession(data);
        vm.stopPrank();
    }

    function testSessionExecute_AttemptDifferentContractWithValue_Reverts() public {
        address other = makeAddr("otherContract");
        (uint128 counter,) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));

        bytes memory args = bytes("");
        bytes memory data = _constructSessionExecuteBytes(signature, counter, deadline, other, 1 ether, args);

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.NotSelf.selector);
        MockDelegate(user).executeSession(data);
        vm.stopPrank();
    }

    function testSessionExecute_SignedByOtherUser_RevertsNotSelf() public {
        (uint128 counter,) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);
        // Sign with USER_PRIVATE_KEY_2 instead of the user's key
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY_2, user, counter, deadline, paymaster, address(mockToken));

        bytes memory args = bytes("");
        bytes memory data = _constructSessionExecuteBytes(signature, counter, deadline, address(mockToken), 0, args);

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.NotSelf.selector);
        MockDelegate(user).executeSession(data);
        vm.stopPrank();
    }

    function testSessionExecuteFallbackNoReturn() public {
        mockToken.mint(user, 10 * 10 ** 18);
        address receiver = makeAddr("receiver");

        (uint128 counter,) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));

        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 5 * 10 ** 18);

        bytes memory data = _constructFallbackCalldata(
            bytes1(0x30),
            signature,
            counter,
            abi.encodePacked(deadline, address(mockToken), _fallbackEncodeEth(0), args)
        );

        vm.prank(paymaster);
        (bool success,) = user.call(data);
        vm.stopPrank();

        assertTrue(success);
        assertEq(mockToken.balanceOf(receiver), 5 * 10 ** 18);
    }

    function testSessionExecuteFallbackWithReturn() public {
        mockToken.mint(user, 10 * 10 ** 18);
        address receiver = makeAddr("receiver");

        (uint128 counter,) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));

        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 5 * 10 ** 18);

        bytes memory data = _constructFallbackCalldata(
            bytes1(0x31),
            signature,
            counter,
            abi.encodePacked(deadline, address(mockToken), _fallbackEncodeEth(0), args)
        );

        vm.prank(paymaster);
        (bool success, bytes memory result) = user.call(data);
        vm.stopPrank();

        assertTrue(success);
        assertEq(abi.decode(result, (bool)), true);
        assertEq(mockToken.balanceOf(receiver), 5 * 10 ** 18);
    }

    // ========== PARAMETERIZED VERSIONS ==========

    function testSessionExecuteParameterized_Succeeds() public {
        mockToken.mint(user, 10 * 10 ** 18);
        address receiver = makeAddr("receiver");

        (uint128 counter,) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));

        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 5 * 10 ** 18);
        // Create data manually: [signature(65)][nonce(16)][deadline(4)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline), args);

        vm.prank(paymaster);
        (bool success,) = MockDelegate(user).executeSession(address(mockToken), 0, data);
        vm.stopPrank();

        assertTrue(success);
        assertEq(mockToken.balanceOf(receiver), 5 * 10 ** 18);
    }

    function testSessionExecuteParameterized_ExpiredDeadline_Reverts() public {
        (uint128 counter,) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp - 1);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));
        bytes memory args = bytes("");
        // Create data manually: [signature(65)][nonce(16)][deadline(4)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline), args);

        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).executeSession(address(mockToken), 0, data);
        vm.stopPrank();
    }

    function testSessionExecuteParameterized_InvalidCounter_Reverts() public {
        (uint128 counter,) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));
        bytes memory args = bytes("");
        // Create data manually: [signature(65)][nonce(16)][deadline(4)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline), args);

        // Burn the counter
        vm.prank(user, user);
        MockDelegate(user).burnSessionCounter();
        vm.stopPrank();

        (uint128 newCounter,) = MockDelegate(user).state();

        assertEq(counter + 1, newCounter);

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.InvalidCounter.selector);
        MockDelegate(user).executeSession(address(mockToken), 0, data);
        vm.stopPrank();
    }

    function testSessionExecuteParameterized_Replayability_AllowsMultipleExecutions() public {
        mockToken.mint(user, 100 ether);
        address receiver = makeAddr("receiver");

        (uint128 counter,) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 5 ether);
        // Create data manually: [signature(65)][nonce(16)][deadline(4)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline), args);

        vm.startPrank(paymaster);
        (bool s1,) = MockDelegate(user).executeSession(address(mockToken), 0, data);
        (bool s2,) = MockDelegate(user).executeSession(address(mockToken), 0, data); // replay with same counter
        vm.stopPrank();

        assertTrue(s1 && s2);
        assertEq(mockToken.balanceOf(receiver), 10 ether);
    }

    function testSessionExecuteParameterized_AttemptDifferentContract_Reverts() public {
        // build a valid signature for mockToken but attempt to call a different contract
        address other = makeAddr("otherContract");
        (uint128 counter,) = MockDelegate(user).state();
        vm.deal(user, 1 ether);
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));

        // args don't matter, target is wrong
        bytes memory args = bytes("");
        // Create data manually: [signature(65)][nonce(16)][deadline(4)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline), args);

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.NotSelf.selector);
        MockDelegate(user).executeSession(other, 0, data);
        vm.stopPrank();
    }

    function testSessionExecuteParameterized_SignedByOtherUser_RevertsNotSelf() public {
        (uint128 counter,) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);
        // Sign with USER_PRIVATE_KEY_2 for 'user'
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY_2, user, counter, deadline, paymaster, address(mockToken));

        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, makeAddr("receiver"), 1 ether);
        // Create data manually: [signature(65)][nonce(16)][deadline(4)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline), args);

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.NotSelf.selector);
        MockDelegate(user).executeSession(address(mockToken), 0, data);
        vm.stopPrank();
    }
}
