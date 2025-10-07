// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {IBatchExecution} from "../../../src/TKGasStation/interfaces/IBatchExecution.sol";
import {MockDelegate} from "../../mocks/MockDelegate.t.sol";
import {MockERC20} from "../../mocks/MockERC20.t.sol";
import {TKGasDelegateTestBase as TKGasDelegateBase} from "../TKGasDelegateTestBase.t.sol";
import {TKGasDelegate} from "../../../src/TKGasStation/TKGasDelegate.sol";

contract BatchSessionTest is TKGasDelegateBase {
    function testBatchSessionExecute_Succeeds() public {
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

        (, uint128 counter) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));

        bytes memory data = abi.encodePacked(signature, counter, deadline, address(mockToken), abi.encode(calls));

        vm.prank(paymaster);
        (bool success, bytes[] memory results) = MockDelegate(user).executeBatchSession(data);
        vm.stopPrank();
        assertTrue(success);
        assertEq(mockToken.balanceOf(receiver), 10 ether);
    }

    function testBatchSessionExecute_InvalidOutputContract_Reverts() public {
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

        (, uint128 counter) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));
        bytes memory data = abi.encodePacked(signature, counter, deadline, address(mockToken), abi.encode(calls));

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.InvalidOutputContract.selector);
        MockDelegate(user).executeBatchSession(data);
        vm.stopPrank();
    }

    function testBatchSessionExecute_ExpiredDeadline_Reverts() public {
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](0);
        (, uint128 counter) = MockDelegate(user).state();
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
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](0);
        (, uint128 counter) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));
        bytes memory data = abi.encodePacked(signature, counter, deadline, address(mockToken), abi.encode(calls));

        vm.prank(user);
        MockDelegate(user).spoof_Counter(counter + 1);
        vm.stopPrank();

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.InvalidCounter.selector);
        MockDelegate(user).executeBatchSession(data);
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

        (, uint128 counter) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));
        bytes memory data = abi.encodePacked(signature, counter, deadline, address(mockToken), abi.encode(calls));

        vm.startPrank(paymaster);
        MockDelegate(user).executeBatchSession(data);
        MockDelegate(user).executeBatchSession(data); // Replay
        vm.stopPrank();

        assertEq(mockToken.balanceOf(receiver), 6 ether);
    }
}
