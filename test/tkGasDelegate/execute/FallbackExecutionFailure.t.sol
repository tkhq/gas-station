// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {MockDelegate} from "../../mocks/MockDelegate.t.sol";
import {TKGasDelegateTestBase as TKGasDelegateBase} from "../TKGasDelegateTestBase.t.sol";
import {TKGasDelegate} from "../../../src/TKGasStation/TKGasDelegate.sol";

contract FallbackExecutionTest is TKGasDelegateBase {
    function testFallbackExecuteSendERC20() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

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

    function testFallbackExecuteSendEth() public {
        address receiver = makeAddr("receiver");
        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory signature = _signExecute(USER_PRIVATE_KEY, user, nonce, receiver, 1 ether, bytes(""));

        bytes memory fallbackData = _constructFallbackCalldata(
            bytes1(0x10), 
            signature, 
            nonce, 
            abi.encodePacked(
                receiver, 
                _fallbackEncodeEth(1 ether), 
                bytes("")
            )
        );

        vm.prank(paymaster);
        vm.deal(user, 1 ether);
        (bool success,) = user.call(fallbackData);
        vm.stopPrank();

        assertTrue(success);
    }


    function testFallbackUnexpectedExecutionMode() public {
        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory signature = _signExecute(USER_PRIVATE_KEY, user, nonce, address(0), 0, bytes(""));

        bytes memory fallbackData = _constructFallbackCalldata(bytes1(0xFF), signature, nonce, bytes(""));

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        (success, result) = user.call(fallbackData);
        vm.stopPrank();

        assertEq(success, false);
        assertEq(result, abi.encodeWithSelector(TKGasDelegate.UnsupportedExecutionMode.selector));
    }
}
