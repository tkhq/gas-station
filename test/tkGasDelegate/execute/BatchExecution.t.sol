// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IBatchExecution} from "../../../src/TKGasStation/interfaces/IBatchExecution.sol";
import {TKGasDelegateTestBase as TKGasDelegateBase} from "../TKGasDelegateTestBase.t.sol";
import {MockDelegate} from "../../mocks/MockDelegate.t.sol";
import {console} from "forge-std/console.sol";
import {TKGasDelegate} from "../../../src/TKGasStation/TKGasDelegate.sol";

contract BatchExecutionTest is TKGasDelegateBase {
    function testExecuteBatchBytesGas() public {
        // Prepare calls: 2 ERC20 mints to user and a pure view call
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](3);

        // Call 1: mockToken.mint(user, 10 ether)
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.mint.selector, user, 10 ether)
        });

        // Call 2: mockToken.mint(user, 20 ether)
        calls[1] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.mint.selector, user, 20 ether)
        });

        // Call 3: mockToken.returnPlusHoldings(1)
        calls[2] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.returnPlusHoldings.selector, 1)
        });

        // Build signed batch
        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory signature = _signBatch(USER_PRIVATE_KEY, user, nonce, calls);

        // Encode as abi.encode(IBatchExecution.Call[])
        bytes memory callsEncoded = abi.encode(calls);

        // Construct calldata: [sig(65)][nonce(16)][abi.encode(calls)]
        bytes memory data = abi.encodePacked(signature, bytes16(nonce), callsEncoded);

        // Execute
        bool success;
        bytes[] memory results;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        (success, results) = MockDelegate(user).executeBatch(data);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        // Assertions
        assertTrue(success);
        // Balance should be 30 ether total minted
        assertEq(mockToken.balanceOf(user), 30 ether);
        // Third call returned value encoded; decode and check >= 1
        assertEq(results.length, 3);
        uint256 ret = abi.decode(results[2], (uint256));
        assertEq(ret, 1 + 30 ether);

        // Log gas
        console.log("=== executeBatch(bytes) Gas ===");
        console.log("Total Gas Used: %s", gasUsed);
    }

    function testExecuteBatchRevertsOnInnerFailure() public {
        // Prepare calls where one will revert: transferFrom without allowance
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](2);

        // Mint tokens to user to have balance
        mockToken.mint(user, 1 ether);

        // Call 1: transferFrom(user -> paymaster, 0.5 ether) without prior approve (should revert)
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSignature("transferFrom(address,address,uint256)", user, paymaster, 0.5 ether)
        });

        // Call 2: no-op view
        calls[1] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.returnPlusHoldings.selector, 0)
        });

        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory signature = _signBatch(USER_PRIVATE_KEY, user, nonce, calls);
        bytes memory data = abi.encodePacked(signature, bytes16(nonce), abi.encode(calls));

        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).executeBatch(data);
    }

    function testExecuteBatchMaxSizeExceededReverts() public {
        // MAX_BATCH_SIZE = 20, build 21 calls
        uint256 maxPlusOne = MockDelegate(user).MAX_BATCH_SIZE() + 1;
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](maxPlusOne);
        for (uint256 i = 0; i < maxPlusOne; i++) {
            calls[i] = IBatchExecution.Call({
                to: address(mockToken),
                value: 0,
                data: abi.encodeWithSelector(mockToken.returnPlusHoldings.selector, i)
            });
        }
        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory signature = _signBatch(USER_PRIVATE_KEY, user, nonce, calls);
        bytes memory data = abi.encodePacked(signature, bytes16(nonce), abi.encode(calls));

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.BatchSizeExceeded.selector);
        MockDelegate(user).executeBatch(data);
    }

    function testExecuteBatchMaxSizeSucceeds() public {
        // MAX_BATCH_SIZE = 20, build exactly 20 calls
        uint256 maxSize = MockDelegate(user).MAX_BATCH_SIZE();
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](maxSize);

        for (uint256 i = 0; i < maxSize; i++) {
            calls[i] = IBatchExecution.Call({
                to: address(mockToken),
                value: 0,
                data: abi.encodeWithSelector(mockToken.mint.selector, user, 1 ether)
            });
        }

        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory signature = _signBatch(USER_PRIVATE_KEY, user, nonce, calls);
        bytes memory data = abi.encodePacked(signature, bytes16(nonce), abi.encode(calls));

        bool success;
        bytes[] memory results;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        (success, results) = MockDelegate(user).executeBatch(data);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        // Assertions
        assertTrue(success);
        assertEq(results.length, maxSize);
        assertEq(mockToken.balanceOf(user), maxSize * 1 ether);

        console.log("=== executeBatch Max Size Gas ===");
        console.log("Total Gas Used: %s", gasUsed);
        console.log("Batch Size: %s", maxSize);
    }

    function testExecuteBatchWrongNonceReverts() public {
        MockDelegate(user).spoof_Nonce(20);
        // Prepare calls
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](2);
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.mint.selector, user, 10 ether)
        });
        calls[1] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.mint.selector, user, 20 ether)
        });

        (, uint128 currentNonce) = MockDelegate(user).state();
        uint128 wrongNonce = currentNonce + 1; // Use wrong nonce

        bytes memory signature = _signBatch(USER_PRIVATE_KEY, user, wrongNonce, calls);
        bytes memory data = abi.encodePacked(signature, bytes16(wrongNonce), abi.encode(calls));

        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).executeBatch(data);
    }

    function testExecuteBatchReplayNonceReverts() public {
        // Build a simple batch of 1 call
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](1);
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.mint.selector, user, 1 ether)
        });

        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory signature = _signBatch(USER_PRIVATE_KEY, user, nonce, calls);
        bytes memory data = abi.encodePacked(signature, bytes16(nonce), abi.encode(calls));

        // First execution succeeds
        vm.prank(paymaster);
        (bool success,) = MockDelegate(user).executeBatch(data);
        assertTrue(success);

        // Second execution with the same calldata must revert (nonce already consumed)
        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).executeBatch(data);
    }

    function testExecuteBatchSignedByOtherUserRevertsNotSelf() public {
        // Simple 1-call batch
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](1);
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.mint.selector, user, 1)
        });

        (, uint128 nonce) = MockDelegate(user).state();
        // Sign with a different private key than `user`
        uint256 OTHER_PRIVATE_KEY = 0xBEEF01;
        bytes memory signature = _signBatch(OTHER_PRIVATE_KEY, user, nonce, calls);
        bytes memory data = abi.encodePacked(signature, bytes16(nonce), abi.encode(calls));

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.NotSelf.selector);
        MockDelegate(user).executeBatch(data);
    }

    function testExecuteBatchFallbackNoReturn() public {
        // Build a simple batch of 1 call
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](2);
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.mint.selector, user, 1 ether)
        });
        calls[1] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.mint.selector, user, 2 ether)
        });

        // Record initial balance
        uint256 initialBalance = mockToken.balanceOf(user);

        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory signature = _signBatch(USER_PRIVATE_KEY, user, nonce, calls);
        bytes memory fallbackData = _constructFallbackCalldata(
            bytes1(0x20),
            signature,
            nonce,
            abi.encode(calls)
        );

        vm.prank(paymaster);
        (bool success,) = user.call(fallbackData);
        assertTrue(success);

        // Assert that the user received the minted tokens
        assertEq(mockToken.balanceOf(user), initialBalance + 1 ether + 2 ether);
    }

    function testExecuteBatchFallbackWithReturn() public {
        // Build a simple batch of 1 call
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](2);
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.mint.selector, user, 1 ether)
        });
        calls[1] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.mint.selector, user, 2 ether)
        });

        // Record initial balance
        uint256 initialBalance = mockToken.balanceOf(user);

        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory signature = _signBatch(USER_PRIVATE_KEY, user, nonce, calls);
        bytes memory fallbackData = _constructFallbackCalldata(
            bytes1(0x21),
            signature,
            nonce,
            abi.encode(calls)
        );

        vm.prank(paymaster);
        (bool success, bytes memory result) = user.call(fallbackData);
        assertTrue(success);

        // Assert that the user received the minted tokens
        assertEq(mockToken.balanceOf(user), initialBalance + 1 ether + 2 ether);
        bytes[] memory results = abi.decode(result, (bytes[]));
        assertEq(results[0], abi.encode(1 ether));
        assertEq(results[1], abi.encode(2 ether));
    }

    // ========== PARAMETERIZED VERSIONS ==========

    function testExecuteBatchParameterizedGas() public {
        // Prepare calls: 2 ERC20 mints to user and a pure view call
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](3);

        // Call 1: mockToken.mint(user, 10 ether)
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.mint.selector, user, 10 ether)
        });

        // Call 2: mockToken.mint(user, 20 ether)
        calls[1] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.mint.selector, user, 20 ether)
        });

        // Call 3: mockToken.returnPlusHoldings(1)
        calls[2] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.returnPlusHoldings.selector, 1)
        });

        // Build signed batch
        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory signature = _signBatch(USER_PRIVATE_KEY, user, nonce, calls);

        // Execute using parameterized version - signature and nonce go in _data
        bytes memory data = abi.encodePacked(signature, bytes16(nonce));
        bool success;
        bytes[] memory results;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        (success, results) = MockDelegate(user).executeBatch(calls, data);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        // Assertions
        assertTrue(success);
        // Balance should be 30 ether total minted
        assertEq(mockToken.balanceOf(user), 30 ether);
        // Third call returned value encoded; decode and check >= 1
        assertEq(results.length, 3);
        uint256 ret = abi.decode(results[2], (uint256));
        assertEq(ret, 1 + 30 ether);

        // Log gas
        console.log("=== executeBatch(IBatchExecution.Call[], bytes) Gas ===");
        console.log("Total Gas Used: %s", gasUsed);
    }

    function testExecuteBatchParameterizedRevertsOnInnerFailure() public {
        // Prepare calls where one will revert: transferFrom without allowance
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](2);

        // Mint tokens to user to have balance
        mockToken.mint(user, 1 ether);

        // Call 1: transferFrom(user -> paymaster, 0.5 ether) without prior approve (should revert)
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSignature("transferFrom(address,address,uint256)", user, paymaster, 0.5 ether)
        });

        // Call 2: no-op view
        calls[1] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.returnPlusHoldings.selector, 0)
        });

        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory signature = _signBatch(USER_PRIVATE_KEY, user, nonce, calls);

        bytes memory data = abi.encodePacked(signature, bytes16(nonce));
        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).executeBatch(calls, data);
    }

    function testExecuteBatchParameterizedMaxSizeExceededReverts() public {
        // MAX_BATCH_SIZE = 20, build 21 calls
        uint256 maxPlusOne = MockDelegate(user).MAX_BATCH_SIZE() + 1;
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](maxPlusOne);
        for (uint256 i = 0; i < maxPlusOne; i++) {
            calls[i] = IBatchExecution.Call({
                to: address(mockToken),
                value: 0,
                data: abi.encodeWithSelector(mockToken.returnPlusHoldings.selector, i)
            });
        }
        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory signature = _signBatch(USER_PRIVATE_KEY, user, nonce, calls);

        bytes memory data = abi.encodePacked(signature, bytes16(nonce));
        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.BatchSizeExceeded.selector);
        MockDelegate(user).executeBatch(calls, data);
    }

    function testExecuteBatchParameterizedMaxSizeSucceeds() public {
        // MAX_BATCH_SIZE = 20, build exactly 20 calls
        uint256 maxSize = MockDelegate(user).MAX_BATCH_SIZE();
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](maxSize);

        for (uint256 i = 0; i < maxSize; i++) {
            calls[i] = IBatchExecution.Call({
                to: address(mockToken),
                value: 0,
                data: abi.encodeWithSelector(mockToken.mint.selector, user, 1 ether)
            });
        }

        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory signature = _signBatch(USER_PRIVATE_KEY, user, nonce, calls);

        bytes memory data = abi.encodePacked(signature, bytes16(nonce));
        bool success;
        bytes[] memory results;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        (success, results) = MockDelegate(user).executeBatch(calls, data);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        // Assertions
        assertTrue(success);
        assertEq(results.length, maxSize);
        assertEq(mockToken.balanceOf(user), maxSize * 1 ether);

        console.log("=== executeBatch(IBatchExecution.Call[], bytes) Max Size Gas ===");
        console.log("Total Gas Used: %s", gasUsed);
        console.log("Batch Size: %s", maxSize);
    }

    function testExecuteBatchParameterizedWrongNonceReverts() public {
        MockDelegate(user).spoof_Nonce(20);
        // Prepare calls
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](2);
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.mint.selector, user, 10 ether)
        });
        calls[1] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.mint.selector, user, 20 ether)
        });

        (, uint128 currentNonce) = MockDelegate(user).state();
        uint128 wrongNonce = currentNonce + 1; // Use wrong nonce

        bytes memory signature = _signBatch(USER_PRIVATE_KEY, user, wrongNonce, calls);

        bytes memory data = abi.encodePacked(signature, bytes16(wrongNonce));
        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).executeBatch(calls, data);
    }

    function testExecuteBatchParameterizedReplayNonceReverts() public {
        // Build a simple batch of 1 call
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](1);
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.mint.selector, user, 1 ether)
        });

        (, uint128 nonce) = MockDelegate(user).state();
        bytes memory signature = _signBatch(USER_PRIVATE_KEY, user, nonce, calls);

        bytes memory data = abi.encodePacked(signature, bytes16(nonce));
        // First execution succeeds
        vm.prank(paymaster);
        (bool success,) = MockDelegate(user).executeBatch(calls, data);
        assertTrue(success);

        // Second execution with the same parameters must revert (nonce already consumed)
        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).executeBatch(calls, data);
    }
}
