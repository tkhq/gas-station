// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {MockDelegate} from "../../mocks/MockDelegate.t.sol";
import {TKGasDelegateTestBase as TKGasDelegateBase} from "../TKGasDelegateTestBase.t.sol";
import {TKGasDelegate} from "../../../src/TKGasStation/TKGasDelegate.sol";

contract ERC20TransfersTest is TKGasDelegateBase {
    function testDirectERC20TransferGas() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        vm.prank(user);
        uint256 gasBefore = gasleft();
        mockToken.transfer(receiver, 10 * 10 ** 18);
        uint256 gasUsed = gasBefore - gasleft();

        // First execution succeeds - if we get here without reverting, it succeeded
        assertEq(mockToken.balanceOf(receiver), 10 * 10 ** 18);

        console.log("=== Direct ERC20 Transfer Analysis ===");
        console.log("Total Gas Used: %s", gasUsed);
    }

    function testExecuteBytesERC20Gas() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver_execute_bytes");

        MockDelegate(user).spoof_Nonce(1);

        uint128 nonce = MockDelegate(user).nonce();
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        bytes memory signature =
            _signExecute(USER_PRIVATE_KEY, user, nonce, uint32(block.timestamp + 86400), address(mockToken), 0, args);

        bytes memory executeData =
            _constructExecuteBytes(signature, nonce, uint32(block.timestamp + 86400), address(mockToken), 0, args);

        bytes memory result;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        result = MockDelegate(user).executeReturns(executeData);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        // Success is implicit - if we get here without reverting, the call succeeded
        assertEq(result.length, 32);
        assertEq(mockToken.balanceOf(receiver), 10 * 10 ** 18);
        uint128 currentNonce = MockDelegate(user).nonce();
        assertEq(currentNonce, nonce + 1);

        console.log("=== execute(bytes) ERC20 Transfer Gas ===");
        console.log("Total Gas Used: %s", gasUsed);
        console.log("Result length: %s", result.length);
        console.logBytes(result);
        bool ret = abi.decode(result, (bool));
        console.log("Decoded return (bool): %s", ret);
    }

    function testExecuteBytesERC20GasNoValue() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver_execute_bytes");

        MockDelegate(user).spoof_Nonce(1);
        uint128 nonce = MockDelegate(user).nonce();
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        bytes memory signature =
            _signExecute(USER_PRIVATE_KEY, user, nonce, uint32(block.timestamp + 86400), address(mockToken), 0, args);

        bytes memory executeData =
            _constructExecuteBytes(signature, nonce, uint32(block.timestamp + 86400), address(mockToken), 0, args);

        bytes memory result;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        result = MockDelegate(user).executeReturns(executeData);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        // Success is implicit - if we get here without reverting, the call succeeded
        assertEq(result.length, 32);
        assertEq(mockToken.balanceOf(receiver), 10 * 10 ** 18);
        uint128 currentNonce = MockDelegate(user).nonce();
        assertEq(currentNonce, nonce + 1);

        console.log("=== execute(bytes) ERC20 Transfer Gas ===");
        console.log("Total Gas Used: %s", gasUsed);
        console.log("Result length: %s", result.length);
        console.logBytes(result);
        bool ret = abi.decode(result, (bool));
        console.log("Decoded return (bool): %s", ret);
    }

    function testExecuteBytesERC20WrongNonceReverts() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver_execute_bytes");

        uint128 currentNonce = MockDelegate(user).nonce();
        uint128 wrongNonce = currentNonce + 1; // Use wrong nonce

        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        bytes memory signature = _signExecute(
            USER_PRIVATE_KEY, user, wrongNonce, uint32(block.timestamp + 86400), address(mockToken), 0, args
        );

        bytes memory executeData =
            _constructExecuteBytes(signature, wrongNonce, uint32(block.timestamp + 86400), address(mockToken), 0, args);

        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).execute(executeData);
    }

    function testExecuteBytesERC20ReplayNonceReverts() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver_execute_bytes");

        uint128 nonce = MockDelegate(user).nonce();
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        bytes memory signature =
            _signExecute(USER_PRIVATE_KEY, user, nonce, uint32(block.timestamp + 86400), address(mockToken), 0, args);
        bytes memory executeData =
            _constructExecuteBytes(signature, nonce, uint32(block.timestamp + 86400), address(mockToken), 0, args);

        // First execution succeeds
        bytes memory result;
        vm.prank(paymaster);
        result = MockDelegate(user).executeReturns(executeData);
        // First execution succeeds - if we get here without reverting, it succeeded
        assertEq(result.length, 32);

        // Replay must revert
        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).execute(executeData);
    }

    function testExecuteBytesERC20SignedByOtherUserRevertsNotSelf() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver_execute_bytes");

        uint128 nonce = MockDelegate(user).nonce();
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);

        uint256 OTHER_PRIVATE_KEY = 0xBEEF03;
        bytes memory signature =
            _signExecute(OTHER_PRIVATE_KEY, user, nonce, uint32(block.timestamp + 86400), address(mockToken), 0, args);
        bytes memory executeData =
            _constructExecuteBytes(signature, nonce, uint32(block.timestamp + 86400), address(mockToken), 0, args);

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.NotSelf.selector);
        MockDelegate(user).execute(executeData);
    }

    // ========== PARAMETERIZED VERSIONS ==========

    function testExecuteParameterizedERC20Gas() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver_execute_param");

        MockDelegate(user).spoof_Nonce(1);
        uint128 nonce = MockDelegate(user).nonce();
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        bytes memory signature =
            _signExecute(USER_PRIVATE_KEY, user, nonce, uint32(block.timestamp + 86400), address(mockToken), 0, args);

        // Create data manually: [signature(65)][nonce(16)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(nonce), bytes4(uint32(block.timestamp + 86400)), args);

        bytes memory result;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        result = MockDelegate(user).executeReturns(address(mockToken), 0, data);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        // Success is implicit - if we get here without reverting, the call succeeded
        assertEq(result.length, 32);
        assertEq(mockToken.balanceOf(receiver), 10 * 10 ** 18);
        uint128 currentNonce = MockDelegate(user).nonce();
        assertEq(currentNonce, nonce + 1);

        console.log("=== execute(address, uint256, bytes) ERC20 Gas ===");
        console.log("Total Gas Used: %s", gasUsed);
    }

    function testExecuteParameterizedERC20WithValueGas() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver_execute_param_value");
        vm.deal(user, 1 ether);
        MockDelegate(user).spoof_Nonce(1);
        uint128 nonce = MockDelegate(user).nonce();
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        bytes memory signature =
            _signExecute(USER_PRIVATE_KEY, user, nonce, uint32(block.timestamp + 86400), address(mockToken), 0, args);

        // Create data manually: [signature(65)][nonce(16)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(nonce), bytes4(uint32(block.timestamp + 86400)), args);

        bytes memory result;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        result = MockDelegate(user).executeReturns(address(mockToken), 0, data);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        // Success is implicit - if we get here without reverting, the call succeeded
        assertEq(result.length, 32);
        assertEq(mockToken.balanceOf(receiver), 10 * 10 ** 18);
        uint128 currentNonce = MockDelegate(user).nonce();
        assertEq(currentNonce, nonce + 1);

        console.log("=== execute(address, uint256, bytes) ERC20 With Value Gas ===");
        console.log("Total Gas Used: %s", gasUsed);
    }

    function testExecuteParameterizedERC20WrongNonceReverts() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        uint128 nonce = MockDelegate(user).nonce();
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        bytes memory signature =
            _signExecute(USER_PRIVATE_KEY, user, nonce, uint32(block.timestamp + 86400), address(mockToken), 0, args);

        // Create data manually: [signature(65)][nonce(16)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(nonce), bytes4(uint32(block.timestamp + 86400)), args);

        // Spoof nonce to make it wrong
        MockDelegate(user).spoof_Nonce(nonce + 1);

        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).execute(address(mockToken), 0, data);
    }

    function testExecuteParameterizedERC20SignedByOtherUserRevertsNotSelf() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        uint128 nonce = MockDelegate(user).nonce();
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        // Sign with USER_PRIVATE_KEY_2 instead of the user's key
        bytes memory signature =
            _signExecute(USER_PRIVATE_KEY_2, user, nonce, uint32(block.timestamp + 86400), address(mockToken), 0, args);

        // Create data manually: [signature(65)][nonce(16)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(nonce), bytes4(uint32(block.timestamp + 86400)), args);

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.NotSelf.selector);
        MockDelegate(user).execute(address(mockToken), 0, data);
    }

    function testExecuteParameterizedERC20ReplayNonceReverts() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        uint128 nonce = MockDelegate(user).nonce();
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        bytes memory signature =
            _signExecute(USER_PRIVATE_KEY, user, nonce, uint32(block.timestamp + 86400), address(mockToken), 0, args);

        // Create data manually: [signature(65)][nonce(16)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(nonce), bytes4(uint32(block.timestamp + 86400)), args);

        // First execution succeeds
        vm.prank(paymaster);
        MockDelegate(user).execute(address(mockToken), 0, data);

        // Second execution with the same calldata must revert (nonce already consumed)
        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).execute(address(mockToken), 0, data);
    }

    function testExecuteNoValueParameterizedERC20Gas() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver_execute_no_value_param");

        MockDelegate(user).spoof_Nonce(1);
        uint128 nonce = MockDelegate(user).nonce();
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        bytes memory signature =
            _signExecute(USER_PRIVATE_KEY, user, nonce, uint32(block.timestamp + 86400), address(mockToken), 0, args);

        // Create data manually: [signature(65)][nonce(16)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(nonce), bytes4(uint32(block.timestamp + 86400)), args);

        bytes memory result;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        result = MockDelegate(user).executeReturns(address(mockToken), 0, data);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        // Success is implicit - if we get here without reverting, the call succeeded
        assertEq(result.length, 32);
        assertEq(mockToken.balanceOf(receiver), 10 * 10 ** 18);
        uint128 currentNonce = MockDelegate(user).nonce();
        assertEq(currentNonce, nonce + 1);

        console.log("=== execute(address, uint256, bytes) ERC20 Gas ===");
        console.log("Total Gas Used: %s", gasUsed);
    }

    function testExecuteNoValueParameterizedERC20WrongNonceReverts() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        uint128 nonce = MockDelegate(user).nonce();
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        bytes memory signature =
            _signExecute(USER_PRIVATE_KEY, user, nonce, uint32(block.timestamp + 86400), address(mockToken), 0, args);

        // Create data manually: [signature(65)][nonce(16)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(nonce), bytes4(uint32(block.timestamp + 86400)), args);

        // Spoof nonce to make it wrong
        MockDelegate(user).spoof_Nonce(nonce + 1);

        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).execute(address(mockToken), 0, data);
    }

    function testExecuteNoValueParameterizedERC20SignedByOtherUserRevertsNotSelf() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        uint128 nonce = MockDelegate(user).nonce();
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        // Sign with USER_PRIVATE_KEY_2 instead of the user's key
        bytes memory signature =
            _signExecute(USER_PRIVATE_KEY_2, user, nonce, uint32(block.timestamp + 86400), address(mockToken), 0, args);

        // Create data manually: [signature(65)][nonce(16)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(nonce), bytes4(uint32(block.timestamp + 86400)), args);

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.NotSelf.selector);
        MockDelegate(user).execute(address(mockToken), 0, data);
    }

    function testExecuteNoValueParameterizedERC20ReplayNonceReverts() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        uint128 nonce = MockDelegate(user).nonce();
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        bytes memory signature =
            _signExecute(USER_PRIVATE_KEY, user, nonce, uint32(block.timestamp + 86400), address(mockToken), 0, args);

        // Create data manually: [signature(65)][nonce(16)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(nonce), bytes4(uint32(block.timestamp + 86400)), args);

        // First execution succeeds
        vm.prank(paymaster);
        MockDelegate(user).execute(address(mockToken), 0, data);

        // Second execution with the same calldata must revert (nonce already consumed)
        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).execute(address(mockToken), 0, data);
    }

    function testExecuteNoReturnGas() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver_execute_no_return");

        MockDelegate(user).spoof_Nonce(1);
        uint128 nonce = MockDelegate(user).nonce();
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        bytes memory signature =
            _signExecute(USER_PRIVATE_KEY, user, nonce, uint32(block.timestamp + 86400), address(mockToken), 0, args);

        // Create data manually: [signature(65)][nonce(16)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(nonce), bytes4(uint32(block.timestamp + 86400)), args);

        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        MockDelegate(user).execute(address(mockToken), 0, data);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        assertEq(mockToken.balanceOf(receiver), 10 * 10 ** 18);
        uint128 currentNonce = MockDelegate(user).nonce();
        assertEq(currentNonce, nonce + 1);

        console.log("=== execute(address, uint256, bytes) ERC20 No Return Gas ===");
        console.log("Total Gas Used: %s", gasUsed);
    }

    function testExecuteWithExpiredDeadlineReverts() public {
        mockToken.mint(user, 100 ether);
        address receiver = makeAddr("receiver");

        uint128 nonce = MockDelegate(user).nonce();
        uint32 expiredDeadline = uint32(block.timestamp - 1); // Deadline in the past
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);

        bytes memory signature =
            _signExecute(USER_PRIVATE_KEY, user, nonce, expiredDeadline, address(mockToken), 0, args);
        bytes memory data =
            abi.encodePacked(signature, bytes16(nonce), bytes4(expiredDeadline), address(mockToken), args);

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.DeadlineExceeded.selector);
        MockDelegate(user).execute(address(mockToken), 0, data);
        vm.stopPrank();
    }
}
