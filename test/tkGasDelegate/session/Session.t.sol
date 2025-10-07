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

        (, uint128 counter) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));

        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 5 * 10 ** 18);
        bytes memory data = _constructSessionExecuteBytes(signature, counter, deadline, address(mockToken), args);

        vm.prank(paymaster);
        (bool success,) = MockDelegate(user).executeSession(data);
        vm.stopPrank();

        assertTrue(success);
        assertEq(mockToken.balanceOf(receiver), 5 * 10 ** 18);
    }

    function testSessionExecute_ExpiredDeadline_Reverts() public {
        (, uint128 counter) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp - 1);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));
        bytes memory args = bytes("");
        bytes memory data = _constructSessionExecuteBytes(signature, counter, deadline, address(mockToken), args);

        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).executeSession(data);
        vm.stopPrank();
    }

    function testSessionExecute_InvalidCounter_Reverts() public {
        (, uint128 counter) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature =
            _signSessionExecuteWithSender(USER_PRIVATE_KEY, user, counter, deadline, paymaster, address(mockToken));
        bytes memory args = bytes("");
        bytes memory data = _constructFallbackSessionCalldata(counter, deadline, signature, address(mockToken), args);

        // Burn the counter
        vm.prank(user, user);
        MockDelegate(user).burnSessionCounter();
        vm.stopPrank();

        (, uint128 newCounter) = MockDelegate(user).state();

        assertEq(counter + 1, newCounter);

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.InvalidCounter.selector);
        MockDelegate(user).executeSession(data);
        vm.stopPrank();
    }

    function testSessionExecute_Replayability_AllowsMultipleExecutions() public {
        mockToken.mint(user, 100 ether);
        address receiver = makeAddr("receiver");

        (, uint128 counter) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);
        bytes memory signature = _signSessionExecute(USER_PRIVATE_KEY, user, counter, deadline, address(mockToken));
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 5 ether);
        bytes memory data = _constructSessionExecuteBytes(signature, counter, deadline, address(mockToken), args);

        vm.startPrank(paymaster);
        (bool s1,) = MockDelegate(user).executeSession(data);
        (bool s2,) = MockDelegate(user).executeSession(data); // replay with same counter
        vm.stopPrank();

        assertTrue(s1 && s2);
        assertEq(mockToken.balanceOf(receiver), 10 ether);
    }
}
