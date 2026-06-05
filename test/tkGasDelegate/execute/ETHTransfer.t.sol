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

        uint128 nonce = MockDelegate(user).nonce();
        bytes memory args = "";
        bytes memory signature =
            _signExecute(USER_PRIVATE_KEY, user, nonce, uint32(block.timestamp + 86400), receiver, ethAmount, args);

        bytes memory executeData =
            _constructExecuteBytes(signature, nonce, uint32(block.timestamp + 86400), receiver, ethAmount, args);

        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        MockDelegate(user).execute(executeData);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        // Success is implicit - if we get here without reverting, the call succeeded
        assertEq(receiver.balance, ethAmount);
        uint128 currentNonce = MockDelegate(user).nonce();
        assertEq(currentNonce, nonce + 1);

        console.log("=== execute(bytes) ETH Transfer Gas ===");
        console.log("Total Gas Used: %s", gasUsed);
    }

    function testExecuteBytesETHNoReturn_Succeeds() public {
        address receiver = makeAddr("receiver_execute_no_return");
        uint256 ethAmount = 1 ether;

        vm.deal(user, 2 ether);
        assertEq(receiver.balance, 0);

        uint128 nonce = MockDelegate(user).nonce();
        bytes memory args = "";
        bytes memory signature =
            _signExecute(USER_PRIVATE_KEY, user, nonce, uint32(block.timestamp + 86400), receiver, ethAmount, args);

        bytes memory executeData =
            _constructExecuteBytes(signature, nonce, uint32(block.timestamp + 86400), receiver, ethAmount, args);

        vm.prank(paymaster);
        MockDelegate(user).execute(executeData);
        vm.stopPrank();

        // Verify the call succeeded
        assertEq(receiver.balance, ethAmount);
        uint128 currentNonce = MockDelegate(user).nonce();
        assertEq(currentNonce, nonce + 1);
    }

    function testExecuteBytesETHWrongNonceReverts() public {
        address payable receiver = payable(makeAddr("receiver"));
        uint256 ethAmount = 1 ether;

        vm.deal(user, 2 ether);

        uint128 currentNonce = MockDelegate(user).nonce();
        uint128 wrongNonce = currentNonce + 1; // Use wrong nonce

        bytes memory signature =
            _signExecute(USER_PRIVATE_KEY, user, wrongNonce, uint32(block.timestamp + 86400), receiver, ethAmount, "");

        bytes memory executeData =
            _constructExecuteBytes(signature, wrongNonce, uint32(block.timestamp + 86400), receiver, ethAmount, "");

        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).execute(executeData);
    }

    function testExecuteBytesETHSignedByOtherUserRevertsNotSelf() public {
        address payable receiver = payable(makeAddr("receiver"));
        uint256 ethAmount = 1 ether;
        vm.deal(user, 2 ether);

        uint128 nonce = MockDelegate(user).nonce();
        uint256 OTHER_PRIVATE_KEY = 0xBEEF04;
        bytes memory signature =
            _signExecute(OTHER_PRIVATE_KEY, user, nonce, uint32(block.timestamp + 86400), receiver, ethAmount, "");
        bytes memory executeData =
            _constructExecuteBytes(signature, nonce, uint32(block.timestamp + 86400), receiver, ethAmount, "");

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.NotSelf.selector);
        MockDelegate(user).execute(executeData);
    }

}
