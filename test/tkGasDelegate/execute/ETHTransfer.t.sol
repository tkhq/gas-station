// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {MockDelegate} from "../../mocks/MockDelegate.t.sol";
import {TKGasDelegateTestBase as TKGasDelegateBase} from "../TKGasDelegateTestBase.t.sol";
import {TKGasDelegate} from "../../../src/TKGasStation/TKGasDelegate.sol";
import {MockContractInteractions} from "../../mocks/MockContractInteractions.t.sol";

contract ETHTransferTest is TKGasDelegateBase {
    function testExecuteBytesETHGas() public {
        address receiver = makeAddr("receiver_execute_bytes_eth");
        uint256 ethAmount = 1 ether;

        vm.deal(user, 2 ether);
        assertEq(receiver.balance, 0);

        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory args = "";
        bytes memory signature = _signExecute(USER_PRIVATE_KEY, user, nonce, receiver, ethAmount, args);

        bytes memory executeData = _constructExecuteBytes(signature, nonce, receiver, ethAmount, args);

        bytes memory result;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        result = MockDelegate(user).execute(executeData);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        // Success is implicit - if we get here without reverting, the call succeeded
        assertEq(result.length, 0);
        assertEq(receiver.balance, ethAmount);
        (, uint128 currentNonce) = MockDelegate(user).state();
        assertEq(currentNonce, nonce + 1);

        console.log("=== execute(bytes) ETH Transfer Gas ===");
        console.log("Total Gas Used: %s", gasUsed);
    }

    function testFallbackExecuteSendETH() public {
        address receiver = makeAddr("receiver");
        uint256 ethAmount = 1 ether;

        vm.deal(user, 2 ether);
        assertEq(address(receiver).balance, 0 ether);

        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory signature = _signExecute(USER_PRIVATE_KEY, user, nonce, receiver, ethAmount, "");

        console.log("=== ETH Transfer Test ===");
        console.log("Nonce: %s", nonce);
        console.log("Signature: %s", vm.toString(signature));
        console.log("ETH Amount: %s", ethAmount);
        console.log("Receiver: %s", receiver);

        bytes memory fallbackData = _constructFallbackCalldataWithETH(nonce, signature, receiver, ethAmount, "");

        console.log("=== Fallback Function Calldata (ETH Transfer) ===");
        console.log("Calldata length: %s bytes", fallbackData.length);
        console.log("Calldata (hex): %s", vm.toString(fallbackData));

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        (success, result) = user.call(fallbackData);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        uint256 receiverBalance = receiver.balance;
        assertEq(receiverBalance, ethAmount);
        assertEq(success, true);
        (, uint128 currentNonce) = MockDelegate(user).state();
        assertEq(currentNonce, nonce + 1);

        console.log("=== Fallback Function ETH Transfer Analysis ===");
        console.log("Total Gas Used: %s", gasUsed);
        console.log("ETH Amount: %s", ethAmount);
    }

    function testExecuteBytesETHWrongNonceReverts() public {
        address payable receiver = payable(makeAddr("receiver"));
        uint256 ethAmount = 1 ether;

        vm.deal(user, 2 ether);

        (, uint128 currentNonce) = MockDelegate(user).state();
        uint128 wrongNonce = currentNonce + 1; // Use wrong nonce

        bytes memory signature = _signExecute(USER_PRIVATE_KEY, user, wrongNonce, receiver, ethAmount, "");

        bytes memory executeData = _constructExecuteBytes(signature, wrongNonce, receiver, ethAmount, "");

        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).execute(executeData);
    }

    function testExecuteBytesETHSignedByOtherUserRevertsNotSelf() public {
        address payable receiver = payable(makeAddr("receiver"));
        uint256 ethAmount = 1 ether;
        vm.deal(user, 2 ether);

        (, uint128 nonce) = MockDelegate(user).state();
        uint256 OTHER_PRIVATE_KEY = 0xBEEF04;
        bytes memory signature = _signExecute(OTHER_PRIVATE_KEY, user, nonce, receiver, ethAmount, "");
        bytes memory executeData = _constructExecuteBytes(signature, nonce, receiver, ethAmount, "");

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.NotSelf.selector);
        MockDelegate(user).execute(executeData);
    }

    function testFallbackExecuteSendEthNoReturn() public {
        address receiver = makeAddr("receiver");
        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory signature = _signExecute(USER_PRIVATE_KEY, user, nonce, receiver, 1 ether, bytes(""));

        bytes memory fallbackData = _constructFallbackCalldata(
            bytes1(0x00), signature, nonce, abi.encodePacked(receiver, _fallbackEncodeEth(1 ether), bytes(""))
        );

        vm.prank(paymaster);
        vm.deal(user, 1 ether);
        (bool success,) = user.call(fallbackData);
        vm.stopPrank();

        assertTrue(success);
    }

    function testFallbackExecuteSendEthWithReturn() public {
        MockContractInteractions mockSwap = new MockContractInteractions();
        (, uint128 nonce) = MockDelegate(user).state();
        vm.deal(user, 2 ether);

        bytes memory data = abi.encodeWithSelector(mockSwap.mockDepositEth.selector);
        bytes memory signature = _signExecute(USER_PRIVATE_KEY, user, nonce, address(mockSwap), 2 ether, data);

        bytes memory fallbackData = _constructFallbackCalldata(
            bytes1(0x01), signature, nonce, abi.encodePacked(address(mockSwap), _fallbackEncodeEth(2 ether), data)
        );

        vm.prank(paymaster);
        (bool success, bytes memory result) = user.call(fallbackData);
        vm.stopPrank();

        assertTrue(success);
        uint256 returnedAmount = abi.decode(result, (uint256));
        assertEq(returnedAmount, 2 ether);
    }
}
