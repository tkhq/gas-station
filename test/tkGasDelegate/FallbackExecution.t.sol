// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {MockDelegate} from "../mocks/MockDelegate.t.sol";
import {TKGasDelegateTestBase as TKGasDelegateBase} from "./TKGasDelegateTestBase.t.sol";

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
            nonce,
            signature,
            address(mockToken),
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
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
}

