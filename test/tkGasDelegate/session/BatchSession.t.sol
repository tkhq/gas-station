// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {IBatchExecution} from "../../../src/TKGasStation/interfaces/IBatchExecution.sol";
import {MockDelegate} from "../../mocks/MockDelegate.t.sol";
import {MockERC20} from "../../mocks/MockERC20.t.sol";
import {TKGasDelegateTestBase as TKGasDelegateBase} from "../TKGasDelegateTestBase.t.sol";
import {TKGasDelegate} from "../../../src/TKGasStation/TKGasDelegate.sol";
import {MockERC20} from "../../mocks/MockERC20.t.sol";

contract BatchSessionTest is TKGasDelegateBase {
    function testBatchSessionExecute_Succeeds() public {
        mockToken.mint(user, 100 ether);
        address receiver = makeAddr("receiver");

        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](2);
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.approve.selector, receiver, 20 ether)
        });
        calls[1] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 ether)
        });

        uint128 counter = 1; // Use fixed counter value
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));

        bytes memory data = abi.encodePacked(signature, counter, deadline, address(mockToken), abi.encode(calls));

        bytes[] memory results;
        vm.prank(paymaster);
        results = MockDelegate(user).executeBatchSessionReturns(data);
        vm.stopPrank();
        // Success is implicit - if we get here without reverting, the call succeeded
        assertEq(results.length, 2);
        assertEq(mockToken.allowance(user, receiver), 20 ether);
        assertEq(mockToken.balanceOf(receiver), 10 ether);
    }

    function testBatchSessionExecute_Corrupted_Offset() public {
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

        // Manually corrupt the length field of the calls array in memory to 1 (should be 2)
        assembly {
            mstore(calls, 1)
            mstore(add(calls, 0x20), 0) // set offset of calls[0] to 0x00
        }
        assertEq(calls.length, 1);

        uint128 counter = 1; // Use fixed counter value
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));

        bytes memory callBytes;
        assembly {
            // Take length and data directly from `calls` memory
            let callsLen := mul(mload(calls), 0x20)
            let callsDataPtr := add(calls, 0x20)
            let totalLen := add(0x20, callsLen)
            callBytes := mload(0x40)
            mstore(callBytes, mload(calls)) // store the "length" (even if corrupted)
            // store the offsets/data after the first 0x20 bytes
            let dst := add(callBytes, 0x20)
            let src := callsDataPtr
            for { let i := 0 } lt(i, callsLen) { i := add(i, 0x20) } { mstore(add(dst, i), mload(add(src, i))) }
            mstore(0x40, add(callBytes, totalLen))
        }
        bytes memory data = abi.encodePacked(signature, counter, deadline, address(mockToken), callBytes);

        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).executeBatchSessionReturns(data);
        vm.stopPrank();

        // result is that it should only execute the first call, so the balance of the receiver should be 0
        assertEq(mockToken.allowance(user, receiver), 0 ether);
        assertEq(mockToken.balanceOf(receiver), 0 ether);
    }

    function testBatchSessionExecute_Length_One_But_Actually_Two_Elements() public {
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

        // Manually corrupt the length field of the calls array in memory to 1 (should be 2)
        assembly {
            mstore(calls, 1)
        }
        assertEq(calls.length, 1);

        uint128 counter = 1; // Use fixed counter value
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));

        bytes memory data = abi.encodePacked(signature, counter, deadline, address(mockToken), abi.encode(calls));

        vm.prank(paymaster);
        MockDelegate(user).executeBatchSessionReturns(data);
        vm.stopPrank();

        // result is that it should only execute the first call, so the balance of the receiver should be 0
        assertEq(mockToken.allowance(user, receiver), 10 ether);
        assertEq(mockToken.balanceOf(receiver), 0 ether);
    }

    function testBatchSessionExecute_Length_Two_But_Actually_One_Element_Reverts() public {
        mockToken.mint(user, 100 ether);
        address receiver = makeAddr("receiver");

        uint128 counter = 1; // Use fixed counter value
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));

        // Manually encode the one and only call with corrupted length = 2
        bytes memory manualCalls = abi.encodePacked(
            uint256(2), // corrupted length field
            abi.encode( // only one element present!
                IBatchExecution.Call({
                    to: address(mockToken),
                    value: 0,
                    data: abi.encodeWithSelector(mockToken.approve.selector, receiver, 10 ether)
                })
            )
        );
        bytes memory data = abi.encodePacked(signature, counter, deadline, address(mockToken), manualCalls);

        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).executeBatchSessionReturns(data);
        vm.stopPrank();

        assertEq(mockToken.allowance(user, receiver), 0 ether);
        assertEq(mockToken.balanceOf(receiver), 0 ether);
    }

    function testBatchSessionExecute_InvalidToContract_Reverts() public {
        mockToken.mint(user, 100 ether);
        address receiver = makeAddr("receiver");
        address other = makeAddr("otherContract");

        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](1);
        // Call to a different contract than provided output
        calls[0] = IBatchExecution.Call({
            to: other,
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, receiver, 1 ether)
        });

        uint128 counter = 1; // Use fixed counter value
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline), address(mockToken));

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.InvalidToContract.selector);
        MockDelegate(user).executeBatchSession(calls, data);
        vm.stopPrank();
    }

    function testBatchSessionExecute_NoReturn_Succeeds() public {
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
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));

        bytes memory data = abi.encodePacked(signature, counter, deadline, address(mockToken), abi.encode(calls));

        vm.prank(paymaster);
        MockDelegate(user).executeBatchSession(data);
        vm.stopPrank();

        // Verify the calls executed successfully
        assertEq(mockToken.balanceOf(receiver), 10 ether);
    }

    function testBatchSessionExecute_ExpiredDeadline_Reverts() public {
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](0);
        uint128 counter = 1; // Use fixed counter value
        uint32 deadline = uint32(block.timestamp - 1);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));
        bytes memory data = abi.encodePacked(signature, counter, deadline, address(mockToken), abi.encode(calls));

        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).executeBatchSession(data);
        vm.stopPrank();
    }

    function testBatchSessionExecute_InvalidCounter_Reverts() public {
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](1);
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, makeAddr("receiver"), 1 ether)
        });
        uint128 counter = 1; // Use fixed counter value
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, makeAddr("receiver"), 1 ether);
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline), address(mockToken), args);

        // Burn the counter
        vm.prank(user, user);
        MockDelegate(user).spoof_burnSessionCounter(counter);
        vm.stopPrank();

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.InvalidCounter.selector);
        MockDelegate(user).executeBatchSession(calls, data);
        vm.stopPrank();
    }

    function testBatchSessionExecute_Replayability_AllowsMultipleExecutions() public {
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
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline), address(mockToken));

        vm.startPrank(paymaster);
        MockDelegate(user).executeBatchSession(calls, data);
        MockDelegate(user).executeBatchSession(calls, data); // Replay
        vm.stopPrank();

        assertEq(mockToken.balanceOf(receiver), 6 ether);
    }

    function testBatchSessionExecute_AttemptDifferentContractCall_Reverts() public {
        mockToken.mint(user, 100 ether);
        address receiver = makeAddr("receiver");
        address other = makeAddr("otherContract");

        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](2);
        // first call is to correct contract
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.approve.selector, receiver, 5 ether)
        });
        // second call attempts a different contract
        calls[1] = IBatchExecution.Call({
            to: other,
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, receiver, 5 ether)
        });

        uint128 counter = 1; // Use fixed counter value
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));

        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline), address(mockToken));

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.InvalidToContract.selector);
        MockDelegate(user).executeBatchSession(calls, data);
        vm.stopPrank();
    }

    function testBatchSessionExecuteFallbackNoReturn() public {
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
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));

        bytes memory data = _constructSessionFallbackCalldata(
            bytes1(0x40), signature, counter, deadline, abi.encodePacked(address(mockToken), abi.encode(calls))
        );

        vm.prank(paymaster);
        (bool success,) = user.call(data);
        vm.stopPrank();

        assertTrue(success);
        assertEq(mockToken.balanceOf(receiver), 10 ether);
    }

    function testBatchSessionExecuteFallbackWithReturn() public {
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
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));

        bytes memory data = _constructSessionFallbackCalldata(
            bytes1(0x41), signature, counter, deadline, abi.encodePacked(address(mockToken), abi.encode(calls))
        );

        vm.prank(paymaster);
        (bool success, bytes memory result) = user.call(data);
        vm.stopPrank();

        assertTrue(success);
        bytes[] memory results = abi.decode(result, (bytes[]));
        assertEq(mockToken.balanceOf(receiver), 10 ether);
        assertTrue(results.length == 2);
        assertTrue(abi.decode(results[0], (bool)));
        assertTrue(abi.decode(results[1], (bool)));
    }

    // ========== PARAMETERIZED VERSIONS ==========

    function testBatchSessionExecuteParameterized_Succeeds() public {
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
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));

        // Create data manually: [signature(65)][nonce(16)][deadline(4)][outputContract(20)]
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline), address(mockToken));

        bytes[] memory results;
        vm.prank(paymaster);
        results = MockDelegate(user).executeBatchSessionReturns(calls, data);
        vm.stopPrank();
        // Success is implicit - if we get here without reverting, the call succeeded
        assertEq(mockToken.balanceOf(receiver), 10 ether);
    }

    function testBatchSessionExecuteParameterized_InvalidToContract_Reverts() public {
        mockToken.mint(user, 100 ether);
        address receiver = makeAddr("receiver");
        address other = makeAddr("otherContract");

        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](1);
        // Call to a different contract than provided output
        calls[0] = IBatchExecution.Call({
            to: other,
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, receiver, 1 ether)
        });

        uint128 counter = 1; // Use fixed counter value
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));
        // Create data manually: [signature(65)][nonce(16)][deadline(4)][outputContract(20)]
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline), address(mockToken));

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.InvalidToContract.selector);
        MockDelegate(user).executeBatchSession(calls, data);
        vm.stopPrank();
    }

    function testBatchSessionExecuteParameterizedReturns_Succeeds() public {
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
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));

        // Create data manually: [signature(65)][counter(16)][deadline(4)][outputContract(20)]
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline), address(mockToken));

        bytes[] memory results;
        vm.prank(paymaster);
        results = MockDelegate(user).executeBatchSessionReturns(calls, data);
        vm.stopPrank();

        // Verify the calls executed successfully and returned expected values
        assertEq(results.length, 2);
        assertTrue(abi.decode(results[0], (bool)));
        assertTrue(abi.decode(results[1], (bool)));
        assertEq(mockToken.balanceOf(receiver), 10 ether);
    }

    function testBatchSessionExecuteParameterized_ExpiredDeadline_Reverts() public {
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](0);
        uint128 counter = 1; // Use fixed counter value
        uint32 deadline = uint32(block.timestamp - 1);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));
        // Create data manually: [signature(65)][nonce(16)][deadline(4)][outputContract(20)]
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline), address(mockToken));

        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).executeBatchSession(calls, data);
        vm.stopPrank();
    }

    function testBatchSessionExecuteParameterized_InvalidCounter_Reverts() public {
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](1);
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, makeAddr("receiver"), 1 ether)
        });
        uint128 counter = 1; // Use fixed counter value
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));
        // Create data manually: [signature(65)][nonce(16)][deadline(4)][outputContract(20)]
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline), address(mockToken));

        // Burn the counter
        vm.prank(user, user);
        MockDelegate(user).burnSessionCounter(counter);
        vm.stopPrank();

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.InvalidCounter.selector);
        MockDelegate(user).executeBatchSession(calls, data);
        vm.stopPrank();
    }

    function testBatchSessionExecuteParameterized_SignedByOtherUser_RevertsNotSelf() public {
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](1);
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, makeAddr("receiver"), 1 ether)
        });
        uint128 counter = 1; // Use fixed counter value
        uint32 deadline = uint32(block.timestamp + 1 days);
        // Sign with USER_PRIVATE_KEY_2 for 'user'
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY_2, user, counter, deadline, paymaster, address(mockToken));
        // Create data manually: [signature(65)][nonce(16)][deadline(4)][outputContract(20)]
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline), address(mockToken));

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.NotSelf.selector);
        MockDelegate(user).executeBatchSession(calls, data);
        vm.stopPrank();
    }

    function testBatchSessionExecute_ValidSignatureWrongSender_RevertsNotSelf() public {
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
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));

        // Use parameterized version to avoid batch size parsing issues
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline), address(mockToken));

        // Attempt to execute from unauthorizedSender instead of paymaster
        vm.prank(unauthorizedSender);
        vm.expectRevert(TKGasDelegate.NotSelf.selector);
        MockDelegate(user).executeBatchSession(calls, data);
        vm.stopPrank();

        // Verify the transaction did not go through
        assertEq(mockToken.balanceOf(receiver), 0);
    }

    function testBatchSessionExecuteParameterized_ValidSignatureWrongSender_RevertsNotSelf() public {
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
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));

        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline), address(mockToken));

        // Attempt to execute from unauthorizedSender instead of paymaster
        vm.prank(unauthorizedSender);
        vm.expectRevert(TKGasDelegate.NotSelf.selector);
        MockDelegate(user).executeBatchSession(calls, data);
        vm.stopPrank();

        // Verify the transaction did not go through
        assertEq(mockToken.balanceOf(receiver), 0);
    }

    function testExecuteBatchSession_DifferentContract_Reverts() public {
        mockToken.mint(user, 100 ether);
        MockERC20 mockToken2 = new MockERC20("Mock Token 2", "MT2");
        mockToken2.mint(user, 100 ether);

        uint128 counter = 1;
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));

        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline), address(mockToken));

        IBatchExecution.Call[] memory attackCalls = new IBatchExecution.Call[](2);
        attackCalls[0] = IBatchExecution.Call({
            to: address(mockToken2),
            value: 0,
            data: abi.encodeWithSelector(mockToken2.approve.selector, paymaster, 10 ether)
        });
        attackCalls[1] = IBatchExecution.Call({
            to: address(mockToken2),
            value: 0,
            data: abi.encodeWithSelector(mockToken2.transfer.selector, paymaster, 5 ether)
        });

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.InvalidToContract.selector);
        MockDelegate(user).executeBatchSession(abi.encodePacked(data, abi.encode(attackCalls)));
        vm.stopPrank();
    }

    function testExecuteBatchSessionParameterized_DifferentContract_Reverts() public {
        mockToken.mint(user, 100 ether);
        MockERC20 mockToken2 = new MockERC20("Mock Token 2", "MT2");
        mockToken2.mint(user, 100 ether);

        uint128 counter = 1;
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));

        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline), address(mockToken));

        IBatchExecution.Call[] memory attackCalls = new IBatchExecution.Call[](2);
        attackCalls[0] = IBatchExecution.Call({
            to: address(mockToken2),
            value: 0,
            data: abi.encodeWithSelector(mockToken2.approve.selector, paymaster, 10 ether)
        });
        attackCalls[1] = IBatchExecution.Call({
            to: address(mockToken2),
            value: 0,
            data: abi.encodeWithSelector(mockToken2.transfer.selector, paymaster, 5 ether)
        });

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.InvalidToContract.selector);
        MockDelegate(user).executeBatchSession(attackCalls, data);
        vm.stopPrank();
    }
}
