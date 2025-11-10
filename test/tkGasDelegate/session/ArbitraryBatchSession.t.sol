// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {IBatchExecution} from "../../../src/TKGasStation/interfaces/IBatchExecution.sol";
import {MockDelegate} from "../../mocks/MockDelegate.t.sol";
import {MockERC20} from "../../mocks/MockERC20.t.sol";
import {TKGasDelegateTestBase as TKGasDelegateBase} from "../TKGasDelegateTestBase.t.sol";
import {TKGasDelegate} from "../../../src/TKGasStation/TKGasDelegate.sol";

contract ArbitraryBatchSessionTest is TKGasDelegateBase {
    function _signArbitrary(uint128 _counter, uint32 _deadline, address _sender) internal returns (bytes memory) {
        address signerAddr = vm.addr(USER_PRIVATE_KEY);
        vm.startPrank(signerAddr);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(USER_PRIVATE_KEY, MockDelegate(user).hashArbitrarySessionExecution(_counter, _deadline, _sender));
        vm.stopPrank();
        return abi.encodePacked(r, s, v);
    }

    function testArbitraryBatchSession_Succeeds() public {
        mockToken.mint(user, 100 ether);
        address receiver = makeAddr("receiver");

        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](2);
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.approve.selector, receiver, 10 ether)
        });
        calls[1] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 ether)
        });

        uint128 counter = 1; // Use fixed counter value
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature = _signArbitrary(counter, deadline, paymaster);
        bytes memory data = abi.encodePacked(signature, counter, deadline, abi.encode(calls));

        bytes[] memory results;
        vm.prank(paymaster);
        results = MockDelegate(user).executeBatchSessionArbitraryReturns(data);
        vm.stopPrank();
        // Success is implicit - if we get here without reverting, the call succeeded
        assertEq(mockToken.balanceOf(receiver), 10 ether);
    }

    function testArbitraryBatchSession_NoReturn_Succeeds() public {
        mockToken.mint(user, 100 ether);
        address receiver = makeAddr("receiver");

        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](2);
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.approve.selector, receiver, 10 ether)
        });
        calls[1] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 ether)
        });

        uint128 counter = 1; // Use fixed counter value
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature = _signArbitrary(counter, deadline, paymaster);
        bytes memory data = abi.encodePacked(signature, counter, deadline, abi.encode(calls));

        vm.prank(paymaster);
        MockDelegate(user).executeBatchSessionArbitrary(data);
        vm.stopPrank();

        // Verify the calls executed successfully
        assertEq(mockToken.balanceOf(receiver), 10 ether);
    }

    function testArbitraryBatchSession_ExpiredDeadline_Reverts() public {
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](0);
        uint128 counter = 1; // Use fixed counter value
        uint32 deadline = uint32(block.timestamp - 1);
        bytes memory signature = _signArbitrary(counter, deadline, paymaster);
        bytes memory data = abi.encodePacked(signature, counter, deadline, abi.encode(calls));

        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).executeBatchSessionArbitrary(data);
        vm.stopPrank();
    }

    function testArbitraryBatchSession_InvalidCounter_Reverts() public {
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](1);
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, makeAddr("receiver"), 1 ether)
        });
        uint128 counter = 1; // Use fixed counter value
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature = _signArbitrary(counter, deadline, paymaster);
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline));

        vm.prank(user);
        MockDelegate(user).spoof_burnSessionCounter(1); // Use fixed counter value
        vm.stopPrank();

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.InvalidCounter.selector);
        MockDelegate(user).executeBatchSessionArbitrary(calls, data);
        vm.stopPrank();
    }

    function testArbitraryBatchSession_Replayability_AllowsMultipleExecutions() public {
        mockToken.mint(user, 100 ether);
        address receiver = makeAddr("receiver");

        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](1);
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, receiver, 2 ether)
        });

        uint128 counter = 1; // Use fixed counter value
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature = _signArbitrary(counter, deadline, paymaster);
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline));

        vm.startPrank(paymaster);
        MockDelegate(user).executeBatchSessionArbitrary(calls, data);
        MockDelegate(user).executeBatchSessionArbitrary(calls, data);
        vm.stopPrank();

        assertEq(mockToken.balanceOf(receiver), 4 ether);
    }

    function testArbitraryBatchSessionFallbackNoReturn() public {
        mockToken.mint(user, 100 ether);
        address receiver = makeAddr("receiver");

        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](2);
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.approve.selector, receiver, 10 ether)
        });
        calls[1] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 ether)
        });

        uint128 counter = 1; // Use fixed counter value
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature = _signArbitrary(counter, deadline, paymaster);

        bytes memory data =
            _constructSessionFallbackCalldata(bytes1(0x60), signature, counter, deadline, abi.encode(calls));

        vm.prank(paymaster);
        (bool success,) = user.call(data);
        vm.stopPrank();

        assertTrue(success);
        assertEq(mockToken.balanceOf(receiver), 10 ether);
    }

    function testArbitraryBatchSessionFallbackWithReturn() public {
        mockToken.mint(user, 100 ether);
        address receiver = makeAddr("receiver");

        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](2);
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.approve.selector, receiver, 10 ether)
        });
        calls[1] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 ether)
        });

        uint128 counter = 1; // Use fixed counter value
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature = _signArbitrary(counter, deadline, paymaster);

        bytes memory data =
            _constructSessionFallbackCalldata(bytes1(0x61), signature, counter, deadline, abi.encode(calls));

        vm.prank(paymaster);
        (bool success, bytes memory result) = user.call(data);
        vm.stopPrank();

        assertTrue(success);
        bytes[] memory results = abi.decode(result, (bytes[]));
        assertEq(results.length, 2);
        assertTrue(abi.decode(results[0], (bool)));
        assertTrue(abi.decode(results[1], (bool)));
        assertEq(mockToken.balanceOf(receiver), 10 ether);
    }

    // ========== PARAMETERIZED VERSIONS ==========

    function testArbitraryBatchSessionExecuteParameterized_Succeeds() public {
        mockToken.mint(user, 100 ether);
        address receiver = makeAddr("receiver");

        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](2);
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.approve.selector, receiver, 10 ether)
        });
        calls[1] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 ether)
        });

        uint128 counter = 1; // Use fixed counter value
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature = _signArbitrary(counter, deadline, paymaster);

        // Create data manually: [signature(65)][counter(16)][deadline(4)]
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline));

        bytes[] memory results;
        vm.prank(paymaster);
        results = MockDelegate(user).executeBatchSessionArbitraryReturns(calls, data);
        vm.stopPrank();

        // Success is implicit - if we get here without reverting, the call succeeded
        assertEq(results.length, 2);
        assertTrue(abi.decode(results[0], (bool)));
        assertTrue(abi.decode(results[1], (bool)));
        assertEq(mockToken.balanceOf(receiver), 10 ether);
    }

    function testArbitraryBatchSessionExecuteParameterized_ExpiredDeadline_Reverts() public {
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](1);
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, makeAddr("receiver"), 1 ether)
        });
        uint128 counter = 1; // Use fixed counter value
        uint32 deadline = uint32(block.timestamp - 1);
        bytes memory signature = _signArbitrary(counter, deadline, paymaster);

        // Create data manually: [signature(65)][counter(16)][deadline(4)]
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline));

        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).executeBatchSessionArbitrary(calls, data);
    }

    function testArbitraryBatchSessionExecuteParameterized_InvalidCounter_Reverts() public {
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](1);
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, makeAddr("receiver"), 1 ether)
        });
        uint128 counter = 1; // Use fixed counter value
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature = _signArbitrary(counter, deadline, paymaster);

        // Create data manually: [signature(65)][counter(16)][deadline(4)]
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline));

        // Burn the counter
        vm.prank(user, user);
        MockDelegate(user).burnSessionCounter(counter);
        vm.stopPrank();

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.InvalidCounter.selector);
        MockDelegate(user).executeBatchSessionArbitrary(calls, data);
        vm.stopPrank();
    }

    function testArbitraryBatchSessionExecuteParameterized_Replayability_AllowsMultipleExecutions() public {
        mockToken.mint(user, 100 ether);
        address receiver = makeAddr("receiver");

        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](1);
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, receiver, 3 ether)
        });

        uint128 counter = 1; // Use fixed counter value
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature = _signArbitrary(counter, deadline, paymaster);

        // Create data manually: [signature(65)][counter(16)][deadline(4)]
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline));

        vm.startPrank(paymaster);
        MockDelegate(user).executeBatchSessionArbitrary(calls, data);
        MockDelegate(user).executeBatchSessionArbitrary(calls, data); // Replay
        vm.stopPrank();

        assertEq(mockToken.balanceOf(receiver), 6 ether);
    }

    function testArbitraryBatchSessionExecuteParameterized_SignedByOtherUser_RevertsNotSelf() public {
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](1);
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, makeAddr("receiver"), 1 ether)
        });
        uint128 counter = 1; // Use fixed counter value
        uint32 deadline = uint32(block.timestamp + 1 days);
        // Sign with USER_PRIVATE_KEY_2 instead of the user's key
        bytes memory signature = _signArbitraryWithKey(USER_PRIVATE_KEY_2, counter, deadline, paymaster);

        // Create data manually: [signature(65)][counter(16)][deadline(4)]
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline));

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.NotSelf.selector);
        MockDelegate(user).executeBatchSessionArbitrary(calls, data);
    }

    function testArbitraryBatchSessionExecuteParameterized_MaxSizeExceeded_Reverts() public {
        // MAX_BATCH_SIZE = 20, build 21 calls
        uint256 maxPlusOne = MockDelegate(user).MAX_BATCH_SIZE() + 1;
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](maxPlusOne);
        for (uint256 i = 0; i < maxPlusOne; i++) {
            calls[i] = IBatchExecution.Call({
                to: address(mockToken),
                value: 0,
                data: abi.encodeWithSelector(mockToken.returnPlusHoldings.selector, i)
            });
        }

        uint128 counter = 1; // Use fixed counter value
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature = _signArbitrary(counter, deadline, paymaster);

        // Create data manually: [signature(65)][counter(16)][deadline(4)]
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline));

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.BatchSizeInvalid.selector);
        MockDelegate(user).executeBatchSessionArbitrary(calls, data);
    }

    function testArbitraryBatchSessionExecuteParameterized_MaxSizeSucceeds() public {
        // MAX_BATCH_SIZE = 20, build exactly 20 calls
        uint256 maxSize = MockDelegate(user).MAX_BATCH_SIZE();
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](maxSize);

        for (uint256 i = 0; i < maxSize; i++) {
            calls[i] = IBatchExecution.Call({
                to: address(mockToken),
                value: 0,
                data: abi.encodeWithSelector(mockToken.mint.selector, user, 1 ether)
            });
        }

        uint128 counter = 1; // Use fixed counter value
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature = _signArbitrary(counter, deadline, paymaster);

        // Create data manually: [signature(65)][counter(16)][deadline(4)]
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline));

        bytes[] memory results;
        vm.prank(paymaster);
        results = MockDelegate(user).executeBatchSessionArbitraryReturns(calls, data);
        vm.stopPrank();

        // Success is implicit - if we get here without reverting, the call succeeded
        assertEq(results.length, maxSize);
        assertEq(mockToken.balanceOf(user), maxSize * 1 ether);
    }

    // Helper function for signing with different private key
    function _signArbitraryWithKey(uint256 _privateKey, uint128 _counter, uint32 _deadline, address _sender)
        internal
        returns (bytes memory)
    {
        address signerAddr = vm.addr(_privateKey);
        vm.startPrank(signerAddr);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(_privateKey, MockDelegate(user).hashArbitrarySessionExecution(_counter, _deadline, _sender));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();
        return signature;
    }

    function testArbitraryBatchSession_ValidSignatureWrongSender_RevertsNotSelf() public {
        // This test verifies that even with a valid signature from the user,
        // if someone other than the authorized sender tries to execute, it should revert
        mockToken.mint(user, 100 ether);
        address receiver = makeAddr("receiver");
        address unauthorizedSender = makeAddr("unauthorizedSender");

        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](1);
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 ether)
        });

        uint128 counter = 1;
        uint32 deadline = uint32(block.timestamp + 1 days);

        // Create a valid signature where 'paymaster' is the authorized sender
        bytes memory signature = _signArbitrary(counter, deadline, paymaster);
        // Use parameterized version to avoid batch size parsing issues
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline));

        // Attempt to execute from unauthorizedSender instead of paymaster
        vm.prank(unauthorizedSender);
        vm.expectRevert(TKGasDelegate.NotSelf.selector);
        MockDelegate(user).executeBatchSessionArbitrary(calls, data);
        vm.stopPrank();

        // Verify the transaction did not go through
        assertEq(mockToken.balanceOf(receiver), 0);
    }

    function testArbitraryBatchSessionExecuteParameterized_ValidSignatureWrongSender_RevertsNotSelf() public {
        // Same test as above but using the parameterized version
        mockToken.mint(user, 100 ether);
        address receiver = makeAddr("receiver");
        address unauthorizedSender = makeAddr("unauthorizedSender");

        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](1);
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 ether)
        });

        uint128 counter = 1;
        uint32 deadline = uint32(block.timestamp + 1 days);

        // Create a valid signature where 'paymaster' is the authorized sender
        bytes memory signature = _signArbitrary(counter, deadline, paymaster);
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline));

        // Attempt to execute from unauthorizedSender instead of paymaster
        vm.prank(unauthorizedSender);
        vm.expectRevert(TKGasDelegate.NotSelf.selector);
        MockDelegate(user).executeBatchSessionArbitrary(calls, data);
        vm.stopPrank();

        // Verify the transaction did not go through
        assertEq(mockToken.balanceOf(receiver), 0);
    }

    function testArbitraryBatchSessionExecute_Corrupted_Offset_Returns() public {
        mockToken.mint(user, 100 ether);
        address receiver = makeAddr("receiver");

        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](2);
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.approve.selector, receiver, 10 ether)
        });
        calls[1] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 ether)
        });

        uint128 counter = 1;
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature = _signArbitrary(counter, deadline, paymaster);

        bytes memory callsEncoded = abi.encode(calls);
        bytes memory data = abi.encodePacked(signature, counter, deadline, callsEncoded);

        // Corrupt the offset pointer in the ABI-encoded calls array (should be 0x20, set to 0x00)
        // Offset pointer is at byte 85 from start of data content (after 32-byte length prefix)
        assembly {
            let offsetPtrStart := add(add(data, 0x20), 85)
            for { let i := 0 } lt(i, 32) { i := add(i, 1) } { mstore8(add(offsetPtrStart, i), 0) }
        }

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.InvalidOffset.selector);
        MockDelegate(user).executeBatchSessionArbitraryReturns(data);
        vm.stopPrank();

        assertEq(mockToken.allowance(user, receiver), 0 ether);
        assertEq(mockToken.balanceOf(receiver), 0 ether);
    }

    function testArbitraryBatchSessionExecute_Corrupted_Offset_NoReturn() public {
        mockToken.mint(user, 100 ether);
        address receiver = makeAddr("receiver");

        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](2);
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.approve.selector, receiver, 10 ether)
        });
        calls[1] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 ether)
        });

        uint128 counter = 1;
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature = _signArbitrary(counter, deadline, paymaster);

        bytes memory callsEncoded = abi.encode(calls);
        bytes memory data = abi.encodePacked(signature, counter, deadline, callsEncoded);

        // Corrupt the offset pointer in the ABI-encoded calls array (should be 0x20, set to 0x00)
        // Offset pointer is at byte 85 from start of data content (after 32-byte length prefix)
        assembly {
            let offsetPtrStart := add(add(data, 0x20), 85)
            for { let i := 0 } lt(i, 32) { i := add(i, 1) } { mstore8(add(offsetPtrStart, i), 0) }
        }

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.InvalidOffset.selector);
        MockDelegate(user).executeBatchSessionArbitrary(data);
        vm.stopPrank();

        assertEq(mockToken.allowance(user, receiver), 0 ether);
        assertEq(mockToken.balanceOf(receiver), 0 ether);
    }
}
