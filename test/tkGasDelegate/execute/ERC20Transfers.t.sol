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
        bool success = mockToken.transfer(receiver, 10 * 10 ** 18);
        uint256 gasUsed = gasBefore - gasleft();

        assertTrue(success);
        assertEq(mockToken.balanceOf(receiver), 10 * 10 ** 18);

        console.log("=== Direct ERC20 Transfer Analysis ===");
        console.log("Total Gas Used: %s", gasUsed);
    }

    function testExecuteBytesERC20Gas() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver_execute_bytes");

        MockDelegate(user).spoof_Nonce(1);

        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        bytes memory signature = _signExecute(USER_PRIVATE_KEY, user, nonce, address(mockToken), 0, args);

        bytes memory executeData = _constructExecuteBytes(signature, nonce, address(mockToken), 0, args);

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        (success, result) = MockDelegate(user).execute(executeData);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        assertEq(success, true);
        assertEq(result.length, 32);
        assertEq(mockToken.balanceOf(receiver), 10 * 10 ** 18);
        (, uint128 currentNonce) = MockDelegate(user).state();
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
        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        bytes memory signature = _signExecute(USER_PRIVATE_KEY, user, nonce, address(mockToken), 0, args);

        bytes memory executeData = _constructExecuteBytes(signature, nonce, address(mockToken), 0, args);

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        (success, result) = MockDelegate(user).execute(executeData);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        assertEq(success, true);
        assertEq(result.length, 32);
        assertEq(mockToken.balanceOf(receiver), 10 * 10 ** 18);
        (, uint128 currentNonce) = MockDelegate(user).state();
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

        (, uint128 currentNonce) = MockDelegate(user).state();
        uint128 wrongNonce = currentNonce + 1; // Use wrong nonce

        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        bytes memory signature = _signExecute(USER_PRIVATE_KEY, user, wrongNonce, address(mockToken), 0, args);

        bytes memory executeData = _constructExecuteBytes(signature, wrongNonce, address(mockToken), 0, args);

        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).execute(executeData);
    }

    function testExecuteBytesERC20ReplayNonceReverts() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver_execute_bytes");

        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        bytes memory signature = _signExecute(USER_PRIVATE_KEY, user, nonce, address(mockToken), 0, args);
        bytes memory executeData = _constructExecuteBytes(signature, nonce, address(mockToken), 0, args);

        // First execution succeeds
        bool success;
        bytes memory result;
        vm.prank(paymaster);
        (success, result) = MockDelegate(user).execute(executeData);
        assertTrue(success);
        assertEq(result.length, 32);

        // Replay must revert
        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).execute(executeData);
    }

    function testExecuteBytesERC20SignedByOtherUserRevertsNotSelf() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver_execute_bytes");

        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);

        uint256 OTHER_PRIVATE_KEY = 0xBEEF03;
        bytes memory signature = _signExecute(OTHER_PRIVATE_KEY, user, nonce, address(mockToken), 0, args);
        bytes memory executeData = _constructExecuteBytes(signature, nonce, address(mockToken), 0, args);

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.NotSelf.selector);
        MockDelegate(user).execute(executeData);
    }

    function testFallbackExecuteSendERC20WithReturn() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");
        MockDelegate(user).spoof_Nonce(1);
        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory signature = _signExecute(
            USER_PRIVATE_KEY,
            user,
            nonce,
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
        );

        console.log("=== Signature ===");
        console.log("Signature: %s", vm.toString(signature));
        console.log("=== Mock contract address ===");
        console.log("Mock contract address: %s", address(mockToken));

        bytes memory fallbackData = _constructFallbackCalldata(
            bytes1(0x01),
            signature,
            nonce,
            abi.encodePacked(
                address(mockToken),
                _fallbackEncodeEth(0),
                abi.encodeWithSelector(mockToken.transfer.selector, receiver, uint256(10 * 10 ** 18))
            )
        );

        console.log("=== Fallback Function Calldata ===");
        console.log("Calldata length: %s bytes", fallbackData.length);
        console.log("Calldata (hex): %s", vm.toString(fallbackData));
        console.log("Calldata (bytes): [%s]", _bytesToHexString(fallbackData));

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        (success, result) = user.call(fallbackData);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        uint256 receiverBalance = mockToken.balanceOf(receiver);
        assertEq(receiverBalance, 10 * 10 ** 18);
        assertEq(success, true);
        (, uint128 currentNonce) = MockDelegate(user).state();
        assertEq(currentNonce, nonce + 1);
        bool ret = abi.decode(result, (bool));


        console.log("=== Fallback Function ERC20 Transfer Analysis ===");
        console.log("Total Gas Used: %s", gasUsed);
        console.log("Transfer Amount: %s", uint256(10 * 10 ** 18));
    }

        function testFallbackExecuteSendERC20NoReturn() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");
        MockDelegate(user).spoof_Nonce(1);
        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory signature = _signExecute(
            USER_PRIVATE_KEY,
            user,
            nonce,
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
        );

        console.log("=== Signature ===");
        console.log("Signature: %s", vm.toString(signature));
        console.log("=== Mock contract address ===");
        console.log("Mock contract address: %s", address(mockToken));

        bytes memory fallbackData = _constructFallbackCalldata(
            bytes1(0x00),
            signature,
            nonce,
            abi.encodePacked(
                address(mockToken),
                _fallbackEncodeEth(0),
                abi.encodeWithSelector(mockToken.transfer.selector, receiver, uint256(10 * 10 ** 18))
            )
        );

        console.log("=== Fallback Function Calldata ===");
        console.log("Calldata length: %s bytes", fallbackData.length);
        console.log("Calldata (hex): %s", vm.toString(fallbackData));
        console.log("Calldata (bytes): [%s]", _bytesToHexString(fallbackData));

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        (success, result) = user.call(fallbackData);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        uint256 receiverBalance = mockToken.balanceOf(receiver);
        assertEq(receiverBalance, 10 * 10 ** 18);
        assertEq(success, true);
        (, uint128 currentNonce) = MockDelegate(user).state();
        assertEq(currentNonce, nonce + 1);

        console.log("=== Fallback Function ERC20 Transfer Analysis ===");
        console.log("Total Gas Used: %s", gasUsed);
        console.log("Transfer Amount: %s", uint256(10 * 10 ** 18));
    }

    // ========== PARAMETERIZED VERSIONS ==========

    function testExecuteParameterizedERC20Gas() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver_execute_param");

        MockDelegate(user).spoof_Nonce(1);
        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        bytes memory signature = _signExecute(USER_PRIVATE_KEY, user, nonce, address(mockToken), 0, args);

        // Create data manually: [signature(65)][nonce(16)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(nonce), args);

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        (success, result) = MockDelegate(user).execute(address(mockToken), 0, data);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        assertEq(success, true);
        assertEq(result.length, 32);
        assertEq(mockToken.balanceOf(receiver), 10 * 10 ** 18);
        (, uint128 currentNonce) = MockDelegate(user).state();
        assertEq(currentNonce, nonce + 1);

        console.log("=== execute(address, uint256, bytes) ERC20 Gas ===");
        console.log("Total Gas Used: %s", gasUsed);
    }

    function testExecuteParameterizedERC20WithValueGas() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver_execute_param_value");
        vm.deal(user, 1 ether);
        MockDelegate(user).spoof_Nonce(1);
        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        bytes memory signature = _signExecute(USER_PRIVATE_KEY, user, nonce, address(mockToken), 0, args);

        // Create data manually: [signature(65)][nonce(16)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(nonce), args);

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        (success, result) = MockDelegate(user).execute(address(mockToken), 0, data);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        assertEq(success, true);
        assertEq(result.length, 32);
        assertEq(mockToken.balanceOf(receiver), 10 * 10 ** 18);
        (, uint128 currentNonce) = MockDelegate(user).state();
        assertEq(currentNonce, nonce + 1);

        console.log("=== execute(address, uint256, bytes) ERC20 With Value Gas ===");
        console.log("Total Gas Used: %s", gasUsed);
    }

    function testExecuteParameterizedERC20WrongNonceReverts() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");
        
        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        bytes memory signature = _signExecute(USER_PRIVATE_KEY, user, nonce, address(mockToken), 0, args);

        // Create data manually: [signature(65)][nonce(16)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(nonce), args);

        // Spoof nonce to make it wrong
        MockDelegate(user).spoof_Nonce(nonce + 1);

        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).execute(address(mockToken), 0, data);
    }

    function testExecuteParameterizedERC20SignedByOtherUserRevertsNotSelf() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        // Sign with USER_PRIVATE_KEY_2 instead of the user's key
        bytes memory signature = _signExecute(USER_PRIVATE_KEY_2, user, nonce, address(mockToken), 0, args);

        // Create data manually: [signature(65)][nonce(16)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(nonce), args);

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.NotSelf.selector);
        MockDelegate(user).execute(address(mockToken), 0, data);
    }

    function testExecuteParameterizedERC20ReplayNonceReverts() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        bytes memory signature = _signExecute(USER_PRIVATE_KEY, user, nonce, address(mockToken), 0, args);

        // Create data manually: [signature(65)][nonce(16)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(nonce), args);

        // First execution succeeds
        vm.prank(paymaster);
        (bool success,) = MockDelegate(user).execute(address(mockToken), 0, data);
        assertTrue(success);

        // Second execution with the same calldata must revert (nonce already consumed)
        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).execute(address(mockToken), 0, data);
    }

    function testExecuteNoValueParameterizedERC20Gas() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver_execute_no_value_param");

        MockDelegate(user).spoof_Nonce(1);
        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        bytes memory signature = _signExecute(USER_PRIVATE_KEY, user, nonce, address(mockToken), 0, args);

        // Create data manually: [signature(65)][nonce(16)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(nonce), args);

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        (success, result) = MockDelegate(user).execute(address(mockToken), 0, data);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        assertEq(success, true);
        assertEq(result.length, 32);
        assertEq(mockToken.balanceOf(receiver), 10 * 10 ** 18);
        (, uint128 currentNonce) = MockDelegate(user).state();
        assertEq(currentNonce, nonce + 1);

        console.log("=== execute(address, uint256, bytes) ERC20 Gas ===");
        console.log("Total Gas Used: %s", gasUsed);
    }

    function testExecuteNoValueParameterizedERC20WrongNonceReverts() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        bytes memory signature = _signExecute(USER_PRIVATE_KEY, user, nonce, address(mockToken), 0, args);

        // Create data manually: [signature(65)][nonce(16)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(nonce), args);

        // Spoof nonce to make it wrong
        MockDelegate(user).spoof_Nonce(nonce + 1);

        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).execute(address(mockToken), 0, data);
    }

    function testExecuteNoValueParameterizedERC20SignedByOtherUserRevertsNotSelf() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        // Sign with USER_PRIVATE_KEY_2 instead of the user's key
        bytes memory signature = _signExecute(USER_PRIVATE_KEY_2, user, nonce, address(mockToken), 0, args);

        // Create data manually: [signature(65)][nonce(16)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(nonce), args);

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.NotSelf.selector);
        MockDelegate(user).execute(address(mockToken), 0, data);
    }

    function testExecuteNoValueParameterizedERC20ReplayNonceReverts() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        bytes memory signature = _signExecute(USER_PRIVATE_KEY, user, nonce, address(mockToken), 0, args);

        // Create data manually: [signature(65)][nonce(16)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(nonce), args);

        // First execution succeeds
        vm.prank(paymaster);
        (bool success,) = MockDelegate(user).execute(address(mockToken), 0, data);
        assertTrue(success);

        // Second execution with the same calldata must revert (nonce already consumed)
        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).execute(address(mockToken), 0, data);
    }

    function testExecuteNoValueNoReturnGasComparison() public {
        mockToken.mint(user, 20 * 10 ** 18);
        
        console.log("=== executeNoValueNoReturn vs All Other Execute Functions Gas Comparison ===");
        
        // Test executeNoValueNoReturn
        MockDelegate(user).spoof_Nonce(1);
        (, uint128 nonce) = MockDelegate(user).state();
        address receiver1 = makeAddr("receiver1");
        bytes memory args1 = abi.encodeWithSelector(mockToken.transfer.selector, receiver1, 10 * 10 ** 18);
        bytes memory signature1 = _signExecute(USER_PRIVATE_KEY, user, nonce, address(mockToken), 0, args1);
        bytes memory data1 = abi.encodePacked(signature1, bytes16(nonce), address(mockToken), args1);
        
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        MockDelegate(user).executeNoValueNoReturn(data1);
        uint256 gasUsedNoReturn = gasBefore - gasleft();
        
        // Test fallback version (0x00)
        MockDelegate(user).spoof_Nonce(1);
        (, nonce) = MockDelegate(user).state();
        address receiver2 = makeAddr("receiver2");
        bytes memory args2 = abi.encodeWithSelector(mockToken.transfer.selector, receiver2, 10 * 10 ** 18);
        bytes memory signature2 = _signExecute(USER_PRIVATE_KEY, user, nonce, address(mockToken), 0, args2);
        
        bytes memory fallbackData = _constructFallbackCalldata(
            bytes1(0x00),
            signature2,
            nonce,
            abi.encodePacked(address(mockToken), _fallbackEncodeEth(0), args2)
        );
        
        vm.prank(paymaster);
        gasBefore = gasleft();
        (bool success,) = address(MockDelegate(user)).call(fallbackData);
        uint256 gasUsedFallback = gasBefore - gasleft();
        
        // Assertions
        assertTrue(success);
        assertEq(mockToken.balanceOf(receiver1), 10 * 10 ** 18);
        assertEq(mockToken.balanceOf(receiver2), 10 * 10 ** 18);
        
        // Gas comparison results
        console.log("executeNoValueNoReturn gas:", gasUsedNoReturn);
        console.log("execute(bytes) gas: 31619 (from testExecuteBytesERC20Gas)");
        console.log("execute(bytes) no value gas: 51596 (from testExecuteBytesERC20GasNoValue)");
        console.log("execute(address, uint256, bytes) gas: 51809 (from testExecuteNoValueParameterizedERC20Gas)");
        console.log("Fallback (0x00) gas:", gasUsedFallback);
        
        // Calculate differences
        uint256 diffVsExecuteBytes = gasUsedNoReturn > 31619 ? 
            gasUsedNoReturn - 31619 : 31619 - gasUsedNoReturn;
        uint256 diffVsExecuteBytesNoValue = gasUsedNoReturn > 51596 ? 
            gasUsedNoReturn - 51596 : 51596 - gasUsedNoReturn;
        uint256 diffVsExecuteNoValueParam = gasUsedNoReturn > 51809 ? 
            gasUsedNoReturn - 51809 : 51809 - gasUsedNoReturn;
        uint256 diffVsFallback = gasUsedNoReturn > gasUsedFallback ? 
            gasUsedNoReturn - gasUsedFallback : gasUsedFallback - gasUsedNoReturn;
        
        console.log("Gas difference vs execute(bytes):", diffVsExecuteBytes);
        console.log("Gas difference vs execute(bytes) no value:", diffVsExecuteBytesNoValue);
        console.log("Gas difference vs execute(address, uint256, bytes):", diffVsExecuteNoValueParam);
        console.log("Gas difference vs Fallback (0x00):", diffVsFallback);
        
        console.log("executeNoValueNoReturn vs execute(bytes): %s efficient", 
                   gasUsedNoReturn < 31619 ? "more" : "less");
        console.log("executeNoValueNoReturn vs execute(bytes) no value: %s efficient", 
                   gasUsedNoReturn < 51596 ? "more" : "less");
        console.log("executeNoValueNoReturn vs execute(address, uint256, bytes): %s efficient", 
                   gasUsedNoReturn < 51809 ? "more" : "less");
        console.log("executeNoValueNoReturn vs Fallback (0x00): %s efficient", 
                   gasUsedNoReturn < gasUsedFallback ? "more" : "less");
    }

    function testExecuteNoReturnGas() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver_execute_no_return");

        MockDelegate(user).spoof_Nonce(1);
        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        bytes memory signature = _signExecute(USER_PRIVATE_KEY, user, nonce, address(mockToken), 0, args);

        // Create data manually: [signature(65)][nonce(16)][args]
        bytes memory data = abi.encodePacked(signature, bytes16(nonce), args);

        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        MockDelegate(user).executeNoReturn(address(mockToken), 0, data);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        assertEq(mockToken.balanceOf(receiver), 10 * 10 ** 18);
        (, uint128 currentNonce) = MockDelegate(user).state();
        assertEq(currentNonce, nonce + 1);

        console.log("=== executeNoReturn(address, uint256, bytes) ERC20 No Return Gas ===");
        console.log("Total Gas Used: %s", gasUsed);
    }
}
