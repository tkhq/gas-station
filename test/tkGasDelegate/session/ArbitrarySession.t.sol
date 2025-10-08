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

        (uint128 counter,) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);

        // Sign for arbitrary session (sender only, no contract lock)
        address signerAddr = vm.addr(USER_PRIVATE_KEY);
        vm.startPrank(signerAddr);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(USER_PRIVATE_KEY, MockDelegate(user).hashArbitrarySessionExecution(counter, deadline, paymaster));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();

        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 ether);
        bytes memory data = abi.encodePacked(signature, counter, deadline, address(mockToken), uint256(0), args);

        vm.prank(paymaster);
        (bool success,) = MockDelegate(user).executeSessionArbitrary(data);
        vm.stopPrank();

        assertTrue(success);
        assertEq(mockToken.balanceOf(receiver), 10 ether);
    }

    function testArbitrarySessionExecute_ExpiredDeadline_Reverts() public {
        (uint128 counter,) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp - 1);

        address signerAddr = vm.addr(USER_PRIVATE_KEY);
        vm.startPrank(signerAddr);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(USER_PRIVATE_KEY, MockDelegate(user).hashArbitrarySessionExecution(counter, deadline, paymaster));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();

        bytes memory data = abi.encodePacked(signature, counter, deadline, address(mockToken), uint256(0), bytes(""));

        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).executeSessionArbitrary(data);
        vm.stopPrank();
    }

    function testArbitrarySessionExecute_InvalidCounter_Reverts() public {
        (uint128 counter,) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);

        address signerAddr = vm.addr(USER_PRIVATE_KEY);
        vm.startPrank(signerAddr);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(USER_PRIVATE_KEY, MockDelegate(user).hashArbitrarySessionExecution(counter, deadline, paymaster));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();

        bytes memory data = abi.encodePacked(signature, counter, deadline, address(mockToken), uint256(0), bytes(""));

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

        (uint128 counter,) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);
        vm.startPrank(user);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(USER_PRIVATE_KEY, MockDelegate(user).hashArbitrarySessionExecution(counter, deadline, paymaster));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();

        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 4 ether);
        bytes memory data = abi.encodePacked(signature, counter, deadline, address(mockToken), uint256(0), args);

        vm.startPrank(paymaster);
        (bool s1,) = MockDelegate(user).executeSessionArbitrary(data);
        (bool s2,) = MockDelegate(user).executeSessionArbitrary(data);
        vm.stopPrank();

        assertTrue(s1 && s2);
        assertEq(mockToken.balanceOf(receiver), 8 ether);
    }

    function testArbitrarySessionExecuteFallbackNoReturn() public {
        mockToken.mint(user, 10 * 10 ** 18);
        address receiver = makeAddr("receiver");

        (uint128 counter,) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);

        // Sign for arbitrary session (sender only, no contract lock)
        address signerAddr = vm.addr(USER_PRIVATE_KEY);
        vm.startPrank(signerAddr);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(USER_PRIVATE_KEY, MockDelegate(user).hashArbitrarySessionExecution(counter, deadline, paymaster));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();

        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 5 * 10 ** 18);
        bytes memory data = _constructFallbackCalldata(
            bytes1(0x50),
            signature,
            counter,
            abi.encodePacked(
                deadline,
                address(mockToken),
                _fallbackEncodeEth(0),
                args
            )
        );

        vm.prank(paymaster);
        (bool success,) = user.call(data);
        vm.stopPrank();

        assertTrue(success);
        assertEq(mockToken.balanceOf(receiver), 5 * 10 ** 18);
    }

    function testArbitrarySessionExecuteFallbackWithReturn() public {
        mockToken.mint(user, 10 * 10 ** 18);
        address receiver = makeAddr("receiver");

        (uint128 counter,) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);

        // Sign for arbitrary session (sender only, no contract lock)
        address signerAddr = vm.addr(USER_PRIVATE_KEY);
        vm.startPrank(signerAddr);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(USER_PRIVATE_KEY, MockDelegate(user).hashArbitrarySessionExecution(counter, deadline, paymaster));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();

        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 5 * 10 ** 18);
        bytes memory data = _constructFallbackCalldata(
            bytes1(0x51),
            signature,
            counter,
            abi.encodePacked(
                deadline,
                address(mockToken),
                _fallbackEncodeEth(0),
                args
            )
        );

        vm.prank(paymaster);
        (bool success, bytes memory result) = user.call(data);
        vm.stopPrank();

        assertTrue(success);
        assertEq(abi.decode(result, (bool)), true);
        assertEq(mockToken.balanceOf(receiver), 5 * 10 ** 18);
    }

    // ========== PARAMETERIZED VERSIONS ==========

    function testArbitrarySessionExecuteParameterized_Succeeds() public {
        mockToken.mint(user, 10 * 10 ** 18);
        address receiver = makeAddr("receiver");

        (uint128 counter,) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);

        // Sign for arbitrary session (sender only, no contract lock)
        address signerAddr = vm.addr(USER_PRIVATE_KEY);
        vm.startPrank(signerAddr);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(USER_PRIVATE_KEY, MockDelegate(user).hashArbitrarySessionExecution(counter, deadline, paymaster));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();

        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 5 * 10 ** 18);
        // Create data manually: [signature(65)][counter(16)][deadline(4)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline), args);

        vm.prank(paymaster);
        (bool success, bytes memory result) = MockDelegate(user).executeSessionArbitrary(address(mockToken), 0, data);
        vm.stopPrank();

        assertTrue(success);
        assertEq(abi.decode(result, (bool)), true);
        assertEq(mockToken.balanceOf(receiver), 5 * 10 ** 18);
    }

    function testArbitrarySessionExecuteParameterized_WithValue_Succeeds() public {
        mockToken.mint(user, 10 * 10 ** 18);
        address receiver = makeAddr("receiver");
        vm.deal(user, 1 ether);

        (uint128 counter,) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);

        // Sign for arbitrary session (sender only, no contract lock)
        address signerAddr = vm.addr(USER_PRIVATE_KEY);
        vm.startPrank(signerAddr);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(USER_PRIVATE_KEY, MockDelegate(user).hashArbitrarySessionExecution(counter, deadline, paymaster));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();

        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 5 * 10 ** 18);
        // Create data manually: [signature(65)][counter(16)][deadline(4)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline), args);

        vm.prank(paymaster);
        (bool success, bytes memory result) = MockDelegate(user).executeSessionArbitrary(address(mockToken), 0, data);
        vm.stopPrank();

        assertTrue(success);
        assertEq(abi.decode(result, (bool)), true);
        assertEq(mockToken.balanceOf(receiver), 5 * 10 ** 18);
    }

    function testArbitrarySessionExecuteParameterized_ExpiredDeadline_Reverts() public {
        (uint128 counter,) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp - 1);

        // Sign for arbitrary session (sender only, no contract lock)
        address signerAddr = vm.addr(USER_PRIVATE_KEY);
        vm.startPrank(signerAddr);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(USER_PRIVATE_KEY, MockDelegate(user).hashArbitrarySessionExecution(counter, deadline, paymaster));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();

        bytes memory args = bytes("");
        // Create data manually: [signature(65)][counter(16)][deadline(4)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline), args);

        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).executeSessionArbitrary(address(mockToken), 0, data);
    }

    function testArbitrarySessionExecuteParameterized_InvalidCounter_Reverts() public {
        (uint128 counter,) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);

        // Sign for arbitrary session (sender only, no contract lock)
        address signerAddr = vm.addr(USER_PRIVATE_KEY);
        vm.startPrank(signerAddr);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(USER_PRIVATE_KEY, MockDelegate(user).hashArbitrarySessionExecution(counter, deadline, paymaster));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();

        bytes memory args = bytes("");
        // Create data manually: [signature(65)][counter(16)][deadline(4)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline), args);

        // Burn the counter
        vm.prank(user, user);
        MockDelegate(user).burnSessionCounter();
        vm.stopPrank();

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.InvalidCounter.selector);
        MockDelegate(user).executeSessionArbitrary(address(mockToken), 0, data);
    }

    function testArbitrarySessionExecuteParameterized_Replayability_AllowsMultipleExecutions() public {
        mockToken.mint(user, 100 ether);
        address receiver = makeAddr("receiver");

        (uint128 counter,) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);

        // Sign for arbitrary session (sender only, no contract lock)
        address signerAddr = vm.addr(USER_PRIVATE_KEY);
        vm.startPrank(signerAddr);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(USER_PRIVATE_KEY, MockDelegate(user).hashArbitrarySessionExecution(counter, deadline, paymaster));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();

        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 5 ether);
        // Create data manually: [signature(65)][counter(16)][deadline(4)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline), args);

        vm.startPrank(paymaster);
        (bool s1,) = MockDelegate(user).executeSessionArbitrary(address(mockToken), 0, data);
        (bool s2,) = MockDelegate(user).executeSessionArbitrary(address(mockToken), 0, data); // replay with same counter
        vm.stopPrank();

        assertTrue(s1 && s2);
        assertEq(mockToken.balanceOf(receiver), 10 ether);
    }

    function testArbitrarySessionExecuteParameterized_SignedByOtherUser_RevertsNotSelf() public {
        (uint128 counter,) = MockDelegate(user).state();
        uint32 deadline = uint32(block.timestamp + 1 days);

        // Sign with USER_PRIVATE_KEY_2 instead of the user's key
        address signerAddr = vm.addr(USER_PRIVATE_KEY_2);
        vm.startPrank(signerAddr);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(USER_PRIVATE_KEY_2, MockDelegate(user).hashArbitrarySessionExecution(counter, deadline, paymaster));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();

        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, makeAddr("receiver"), 1 ether);
        // Create data manually: [signature(65)][counter(16)][deadline(4)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(counter), bytes4(deadline), args);

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.NotSelf.selector);
        MockDelegate(user).executeSessionArbitrary(address(mockToken), 0, data);
    }
}
