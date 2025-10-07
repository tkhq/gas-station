pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {MockDelegate} from "../mocks/MockDelegate.t.sol";
import {TKGasDelegateTestBase as TKGasDelegateBase} from "./TKGasDelegateTestBase.t.sol";

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

        MockDelegate(user).spoof_Nonce(1000);

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

        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        bytes memory signature = _signExecute(USER_PRIVATE_KEY, user, nonce, address(mockToken), 0, args);

        bytes memory executeData = _constructExecuteBytesNoValue(signature, nonce, address(mockToken), args);

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        (success, result) = MockDelegate(user).executeNoValue(executeData);
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
}