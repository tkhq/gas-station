// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {TKGasDelegate} from "../../src/TKGasStation/TKGasDelegate.sol";
import {IBatchExecution} from "../../src/TKGasStation/interfaces/IBatchExecution.sol";
import {MockERC20} from "../mocks/MockERC20.sol";
import {TKGasDelegateTestBase} from "./TKGasDelegateTestBase.sol";

contract BatchExecutionTest is TKGasDelegateTestBase {
    function testExecuteBatchBytesGas() public {
        mockToken.mint(user, 50 * 10 ** 18);
        address receiver1 = makeAddr("receiver1_bytes_batch");
        address receiver2 = makeAddr("receiver2_bytes_batch");

        (, uint128 nonce) = TKGasDelegate(user).state();

        IBatchExecution.Call[] memory executions = new IBatchExecution.Call[](2);
        executions[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, receiver1, 10 * 10 ** 18)
        });
        executions[1] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, receiver2, 15 * 10 ** 18)
        });

        bytes memory signature = _signBatch(USER_PRIVATE_KEY, user, nonce, executions);

        bytes16 nonce16 = bytes16(uint128(nonce));
        bytes memory batchData = abi.encode(executions);
        bytes memory executeData = abi.encodePacked(signature, nonce16, batchData);

        bool success;
        bytes[] memory results;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        (success, results) = TKGasDelegate(user).executeBatch(executeData);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        assertTrue(success);
        assertEq(results.length, 2);
        assertEq(mockToken.balanceOf(receiver1), 10 * 10 ** 18);
        assertEq(mockToken.balanceOf(receiver2), 15 * 10 ** 18);
        assertEq(mockToken.balanceOf(user), 25 * 10 ** 18);
        (, uint128 currentNonce) = TKGasDelegate(user).state();
        assertEq(currentNonce, nonce + 1);

        console.log("=== executeBatch(bytes) Gas ===");
        console.log("Total Gas Used: %s", gasUsed);
    }
}
