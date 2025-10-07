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

        (, uint128 counter) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature = _signArbitrary(counter, deadline, paymaster);
        bytes memory data = abi.encodePacked(signature, counter, deadline, abi.encode(calls));

        vm.prank(paymaster);
        (bool success, bytes[] memory results) = MockDelegate(user).executeBatchSessionArbitrary(data);
        vm.stopPrank();
        assertTrue(success);
        assertEq(mockToken.balanceOf(receiver), 10 ether);
    }

    function testArbitraryBatchSession_ExpiredDeadline_Reverts() public {
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](0);
        (, uint128 counter) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp - 1);
        bytes memory signature = _signArbitrary(counter, deadline, paymaster);
        bytes memory data = abi.encodePacked(signature, counter, deadline, abi.encode(calls));

        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).executeBatchSessionArbitrary(data);
        vm.stopPrank();
    }

    function testArbitraryBatchSession_InvalidCounter_Reverts() public {
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](0);
        (, uint128 counter) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature = _signArbitrary(counter, deadline, paymaster);
        bytes memory data = abi.encodePacked(signature, counter, deadline, abi.encode(calls));

        vm.prank(user);
        MockDelegate(user).spoof_Counter(counter + 1);
        vm.stopPrank();

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.InvalidCounter.selector);
        MockDelegate(user).executeBatchSessionArbitrary(data);
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

        (, uint128 counter) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature = _signArbitrary(counter, deadline, paymaster);
        bytes memory data = abi.encodePacked(signature, counter, deadline, abi.encode(calls));

        vm.startPrank(paymaster);
        MockDelegate(user).executeBatchSessionArbitrary(data);
        MockDelegate(user).executeBatchSessionArbitrary(data);
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

        (, uint128 counter) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature = _signArbitrary(counter, deadline, paymaster);

        bytes memory data = _constructFallbackCalldata(
            bytes1(0x70),
            signature,
            counter,
            abi.encodePacked(
                deadline,
                abi.encode(calls)
            )
        );

        vm.prank(paymaster);
        (bool success, ) = user.call(data);
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

        (, uint128 counter) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature = _signArbitrary(counter, deadline, paymaster);

        bytes memory data = _constructFallbackCalldata(
            bytes1(0x71),
            signature,
            counter,
            abi.encodePacked(
                deadline,
                abi.encode(calls)
            )
        );

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
}
