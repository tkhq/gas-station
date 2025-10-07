// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {MockDelegate} from "../../mocks/MockDelegate.t.sol";
import {MockERC20} from "../../mocks/MockERC20.t.sol";
import {TKGasDelegateTestBase as TKGasDelegateBase} from "../TKGasDelegateTestBase.t.sol";
import {TKGasDelegate} from "../../../src/TKGasStation/TKGasDelegate.sol";

contract ArbitrarySessionTest is TKGasDelegateBase {
    function testArbitrarySessionExecute_Succeeds() public {
        mockToken.mint(user, 100 ether);
        address receiver = makeAddr("receiver");

        (, uint128 counter) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);

        // Sign for arbitrary session (sender only, no contract lock)
        address signerAddr = vm.addr(USER_PRIVATE_KEY);
        vm.startPrank(signerAddr);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(USER_PRIVATE_KEY, MockDelegate(user).hashArbitrarySessionExecution(counter, deadline, paymaster));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();

        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 ether);
        bytes memory data = abi.encodePacked(signature, counter, deadline, address(mockToken), args);

        vm.prank(paymaster);
        (bool success,) = MockDelegate(user).executeSessionArbitrary(data);
        vm.stopPrank();

        assertTrue(success);
        assertEq(mockToken.balanceOf(receiver), 10 ether);
    }

    function testArbitrarySessionExecute_ExpiredDeadline_Reverts() public {
        (, uint128 counter) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp - 1);

        address signerAddr = vm.addr(USER_PRIVATE_KEY);
        vm.startPrank(signerAddr);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(USER_PRIVATE_KEY, MockDelegate(user).hashArbitrarySessionExecution(counter, deadline, paymaster));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();

        bytes memory data = abi.encodePacked(signature, counter, deadline, address(mockToken), bytes(""));

        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).executeSessionArbitrary(data);
        vm.stopPrank();
    }

    function testArbitrarySessionExecute_InvalidCounter_Reverts() public {
        (, uint128 counter) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);

        address signerAddr = vm.addr(USER_PRIVATE_KEY);
        vm.startPrank(signerAddr);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(USER_PRIVATE_KEY, MockDelegate(user).hashArbitrarySessionExecution(counter, deadline, paymaster));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();

        bytes memory data = abi.encodePacked(signature, counter, deadline, address(mockToken), bytes(""));

        vm.prank(user);
        MockDelegate(user).spoof_Counter(counter + 1);
        vm.stopPrank();

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.InvalidCounter.selector);
        MockDelegate(user).executeSessionArbitrary(data);
        vm.stopPrank();
    }

    function testArbitrarySessionExecute_Replayability_AllowsMultipleExecutions() public {
        mockToken.mint(user, 100 ether);
        address receiver = makeAddr("receiver");

        (, uint128 counter) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);
        address signerAddr = vm.addr(USER_PRIVATE_KEY);
        vm.startPrank(signerAddr);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(USER_PRIVATE_KEY, MockDelegate(user).hashArbitrarySessionExecution(counter, deadline, signerAddr));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();

        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 4 ether);
        bytes memory data = abi.encodePacked(signature, counter, deadline, address(mockToken), args);

        vm.startPrank(paymaster);
        (bool s1,) = MockDelegate(user).executeSessionArbitrary(data);
        (bool s2,) = MockDelegate(user).executeSessionArbitrary(data);
        vm.stopPrank();

        assertTrue(s1 && s2);
        assertEq(mockToken.balanceOf(receiver), 8 ether);
    }
}
