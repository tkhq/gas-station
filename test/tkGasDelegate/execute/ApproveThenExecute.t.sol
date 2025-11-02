// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {MockDelegate} from "../../mocks/MockDelegate.t.sol";
import {MockERC20} from "../../mocks/MockERC20.t.sol";
import {MockUSDT} from "../../mocks/MockUSDT.t.sol";
import {MockERC20ApproveNotRevert} from "../../mocks/MockERC20ApproveNotRevert.t.sol";
import {MockContractInteractions} from "../../mocks/MockContractInteractions.t.sol";
import {TKGasDelegateTestBase} from "../TKGasDelegateTestBase.t.sol";
import {TKGasDelegate} from "../../../src/TKGasStation/TKGasDelegate.sol";

contract ApproveThenExecuteTest is TKGasDelegateTestBase {
    MockERC20 public tokenA;
    MockERC20 public tokenB;
    MockContractInteractions public mockSwap;

    function setUp() public override {
        super.setUp();

        // Deploy additional mock tokens
        tokenA = new MockERC20("TokenA", "TKA");
        tokenB = new MockERC20("TokenB", "TKB");

        // Deploy mock swap contract
        mockSwap = new MockContractInteractions();

        // Mint tokens to user
        tokenA.mint(user, 1000 * 10 ** 18);
        tokenB.mint(user, 1000 * 10 ** 18);

        // Mint tokens to mock swap contract for liquidity
        tokenA.mint(address(mockSwap), 10000 * 10 ** 18);
        tokenB.mint(address(mockSwap), 10000 * 10 ** 18);
    }

    function testApproveThenExecuteSwap() public {
        uint256 swapAmount = 100 * 10 ** 18;
        uint256 expectedOutput = 95 * 10 ** 18; // 5% slippage

        uint128 nonce = MockDelegate(user).nonce();

        bytes memory swapData = abi.encodeWithSelector(
            mockSwap.mockSwap.selector, address(tokenA), address(tokenB), swapAmount, expectedOutput
        );

        // Create the approve then execute signature
        bytes memory signature = _signApproveThenExecute(
            USER_PRIVATE_KEY,
            user,
            nonce,
            uint32(block.timestamp + 86400),
            address(tokenA),
            address(mockSwap),
            swapAmount,
            address(mockSwap),
            0,
            swapData
        );

        // Construct calldata
        bytes memory executeData = _constructApproveThenExecuteBytes(
            signature,
            nonce,
            uint32(block.timestamp + 86400),
            address(tokenA),
            address(mockSwap),
            swapAmount,
            address(mockSwap),
            0,
            swapData
        );

        // Execute approve then execute
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        bytes memory result = MockDelegate(user).approveThenExecuteReturns(executeData);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        // Success is implicit - if we get here without reverting, the call succeeded
        assertEq(tokenA.balanceOf(user), 900 * 10 ** 18); // 1000 - 100
        assertEq(tokenB.balanceOf(user), 1095 * 10 ** 18); // 1000 + 95
        assertEq(tokenA.balanceOf(address(mockSwap)), 10100 * 10 ** 18); // 10000 + 100
        assertEq(tokenB.balanceOf(address(mockSwap)), 9905 * 10 ** 18); // 10000 - 95

        uint128 currentNonce = MockDelegate(user).nonce();
        assertEq(currentNonce, nonce + 1);

        console.log("=== Approve Then Execute Swap Gas ===");
        console.log("Total Gas Used: %s", gasUsed);
    }

    function testApproveThenExecuteSwapWithETH() public {
        // silly test, might not be needed
        uint256 swapAmount = 50 * 10 ** 18;
        uint256 ethAmount = 0.1 ether;
        uint256 expectedOutput = 47 * 10 ** 18; // 6% slippage

        // Fund the user with ETH
        vm.deal(user, 1 ether);

        uint128 nonce = MockDelegate(user).nonce();

        bytes memory swapData = abi.encodeWithSelector(
            mockSwap.mockSwap.selector, address(tokenA), address(tokenB), swapAmount, expectedOutput
        );

        // Create the approve then execute signature with ETH
        bytes memory signature = _signApproveThenExecute(
            USER_PRIVATE_KEY,
            user,
            nonce,
            uint32(block.timestamp + 86400),
            address(tokenA),
            address(mockSwap),
            swapAmount,
            address(mockSwap),
            ethAmount,
            swapData
        );

        // Construct calldata
        bytes memory executeData = _constructApproveThenExecuteBytes(
            signature,
            nonce,
            uint32(block.timestamp + 86400),
            address(tokenA),
            address(mockSwap),
            swapAmount,
            address(mockSwap),
            ethAmount,
            swapData
        );

        // Execute approve then execute with ETH
        bytes memory result;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        result = MockDelegate(user).approveThenExecuteReturns(executeData);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        // Success is implicit - if we get here without reverting, the call succeeded
        assertEq(tokenA.balanceOf(user), 950 * 10 ** 18); // 1000 - 50
        assertEq(tokenB.balanceOf(user), 1047 * 10 ** 18); // 1000 + 47
        assertEq(tokenA.balanceOf(address(mockSwap)), 10050 * 10 ** 18); // 10000 + 50
        assertEq(tokenB.balanceOf(address(mockSwap)), 9953 * 10 ** 18); // 10000 - 47

        uint128 currentNonce = MockDelegate(user).nonce();
        assertEq(currentNonce, nonce + 1);

        console.log("=== Approve Then Execute Swap with ETH Gas ===");
        console.log("Total Gas Used: %s", gasUsed);
    }

    function testApproveThenExecuteWithUSDT() public {
        // Deploy MockUSDT with special approval logic
        MockUSDT usdt = new MockUSDT("Tether USD", "USDT");

        // Mint USDT to user
        usdt.mint(user, 1000 * 10 ** 6); // USDT has 6 decimals

        uint256 approveAmount = 100 * 10 ** 6; // 100 USDT

        // First, give some allowance to mockSwap (this will require reset to 0 later)
        vm.prank(user);
        usdt.approve(address(mockSwap), 50 * 10 ** 6); // 50 USDT allowance

        // Verify initial allowance
        assertEq(usdt.allowance(user, address(mockSwap)), 50 * 10 ** 6);

        uint128 nonce = MockDelegate(user).nonce();

        // Simple transfer to mockSwap (no swap, just approve and transfer)
        bytes memory transferData = abi.encodeWithSelector(usdt.transfer.selector, address(mockSwap), approveAmount);

        // Create the approve then execute signature
        bytes memory signature = _signApproveThenExecute(
            USER_PRIVATE_KEY,
            user,
            nonce,
            uint32(block.timestamp + 86400),
            address(usdt),
            address(mockSwap),
            approveAmount,
            address(usdt), // Call USDT contract directly
            0,
            transferData
        );

        // Construct calldata
        bytes memory executeData = _constructApproveThenExecuteBytes(
            signature,
            nonce,
            uint32(block.timestamp + 86400),
            address(usdt),
            address(mockSwap),
            approveAmount,
            address(usdt),
            0,
            transferData
        );

        // Execute approve then execute - this should handle USDT's special approval logic
        bytes memory result;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        result = MockDelegate(user).approveThenExecuteReturns(executeData);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        // Success is implicit - if we get here without reverting, the call succeeded
        assertEq(usdt.balanceOf(user), 900 * 10 ** 6); // 1000 - 100
        assertEq(usdt.balanceOf(address(mockSwap)), 100 * 10 ** 6); // 0 + 100
        assertEq(usdt.allowance(user, address(mockSwap)), approveAmount); // Should be updated to new amount

        uint128 currentNonce = MockDelegate(user).nonce();
        assertEq(currentNonce, nonce + 1);

        console.log("=== Approve Then Execute with USDT Gas ===");
        console.log("Total Gas Used: %s", gasUsed);
        console.log("USDT Balance User: %s", usdt.balanceOf(user));
        console.log("USDT Balance MockSwap: %s", usdt.balanceOf(address(mockSwap)));
        console.log("USDT Allowance: %s", usdt.allowance(user, address(mockSwap)));
    }

    function testApproveThenExecuteNoReturn_Succeeds() public {
        uint256 swapAmount = 100 * 10 ** 18;
        uint256 expectedOutput = 95 * 10 ** 18;

        uint128 nonce = MockDelegate(user).nonce();

        bytes memory swapData = abi.encodeWithSelector(
            mockSwap.mockSwap.selector, address(tokenA), address(tokenB), swapAmount, expectedOutput
        );

        bytes memory signature = _signApproveThenExecute(
            USER_PRIVATE_KEY,
            user,
            nonce,
            uint32(block.timestamp + 86400),
            address(tokenA),
            address(mockSwap),
            swapAmount,
            address(mockSwap),
            0,
            swapData
        );

        bytes memory executeData = _constructApproveThenExecuteBytes(
            signature,
            nonce,
            uint32(block.timestamp + 86400),
            address(tokenA),
            address(mockSwap),
            swapAmount,
            address(mockSwap),
            0,
            swapData
        );

        vm.prank(paymaster);
        MockDelegate(user).approveThenExecute(executeData);
        vm.stopPrank();

        // Verify the swap succeeded
        assertEq(tokenA.balanceOf(user), 900 * 10 ** 18); // 1000 - 100
        assertEq(tokenB.balanceOf(user), 1095 * 10 ** 18); // 1000 + 95
        assertEq(tokenA.balanceOf(address(mockSwap)), 10100 * 10 ** 18); // 10000 + 100
        assertEq(tokenB.balanceOf(address(mockSwap)), 9905 * 10 ** 18); // 10000 - 95

        uint128 currentNonce = MockDelegate(user).nonce();
        assertEq(currentNonce, nonce + 1);
    }

    function testApproveThenExecuteWrongNonceReverts() public {
        uint256 swapAmount = 100 * 10 ** 18;
        uint256 expectedOutput = 95 * 10 ** 18;

        uint128 currentNonce = MockDelegate(user).nonce();
        uint128 wrongNonce = currentNonce + 1; // Use wrong nonce

        bytes memory swapData = abi.encodeWithSelector(
            mockSwap.mockSwap.selector, address(tokenA), address(tokenB), swapAmount, expectedOutput
        );

        bytes memory signature = _signApproveThenExecute(
            USER_PRIVATE_KEY,
            user,
            wrongNonce, // Wrong nonce
            uint32(block.timestamp + 86400),
            address(tokenA),
            address(mockSwap),
            swapAmount,
            address(mockSwap),
            0,
            swapData
        );

        bytes memory executeData = _constructApproveThenExecuteBytes(
            signature,
            wrongNonce,
            uint32(block.timestamp + 86400),
            address(tokenA),
            address(mockSwap),
            swapAmount,
            address(mockSwap),
            0,
            swapData
        );

        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).approveThenExecute(executeData);
    }

    function testApproveThenExecuteReplayNonceReverts() public {
        uint256 swapAmount = 10 * 10 ** 18;
        uint256 expectedOutput = 9 * 10 ** 18;
        uint128 nonce = MockDelegate(user).nonce();

        bytes memory swapData = abi.encodeWithSelector(
            mockSwap.mockSwap.selector, address(tokenA), address(tokenB), swapAmount, expectedOutput
        );

        bytes memory signature = _signApproveThenExecute(
            USER_PRIVATE_KEY,
            user,
            nonce,
            uint32(block.timestamp + 86400),
            address(tokenA),
            address(mockSwap),
            swapAmount,
            address(mockSwap),
            0,
            swapData
        );

        bytes memory executeData = _constructApproveThenExecuteBytes(
            signature,
            nonce,
            uint32(block.timestamp + 86400),
            address(tokenA),
            address(mockSwap),
            swapAmount,
            address(mockSwap),
            0,
            swapData
        );

        bytes memory result;
        // First execution succeeds
        vm.prank(paymaster);
        result = MockDelegate(user).approveThenExecuteReturns(executeData);
        // Success is implicit - if we get here without reverting, the call succeeded

        // Replay must revert
        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).approveThenExecute(executeData);
    }

    function testApproveThenExecuteSignedByOtherUserRevertsNotSelf() public {
        uint256 approveAmount = 10 * 10 ** 18;
        uint128 nonce = MockDelegate(user).nonce();

        bytes memory swapData = abi.encodeWithSelector(
            mockSwap.mockSwap.selector, address(tokenA), address(tokenB), approveAmount, 9 * 10 ** 18
        );

        uint256 OTHER_PRIVATE_KEY = 0xBEEF02;
        bytes memory signature = _signApproveThenExecute(
            OTHER_PRIVATE_KEY,
            user,
            nonce,
            uint32(block.timestamp + 86400),
            address(tokenA),
            address(mockSwap),
            approveAmount,
            address(mockSwap),
            0,
            swapData
        );

        bytes memory executeData = _constructApproveThenExecuteBytes(
            signature,
            nonce,
            uint32(block.timestamp + 86400),
            address(tokenA),
            address(mockSwap),
            approveAmount,
            address(mockSwap),
            0,
            swapData
        );

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.NotSelf.selector);
        MockDelegate(user).approveThenExecute(executeData);
    }

    function testFallbackExecutionNoReturn() public {
        uint256 swapAmount = 100 * 10 ** 18;
        uint256 expectedOutput = 95 * 10 ** 18; // 5% slippage

        MockDelegate(user).spoof_Nonce(5000);

        uint128 nonce = MockDelegate(user).nonce();

        bytes memory swapData = abi.encodeWithSelector(
            mockSwap.mockSwap.selector, address(tokenA), address(tokenB), swapAmount, expectedOutput
        );

        // Create the approve then execute signature
        bytes memory signature = _signApproveThenExecute(
            USER_PRIVATE_KEY,
            user,
            nonce,
            uint32(block.timestamp + 86400),
            address(tokenA),
            address(mockSwap),
            swapAmount,
            address(mockSwap),
            0,
            swapData
        );

        bytes memory fallbackExecuteData = _constructFallbackCalldata(
            0x10,
            signature,
            nonce,
            uint32(block.timestamp + 86400),
            abi.encodePacked(
                address(tokenA), address(mockSwap), swapAmount, address(mockSwap), _fallbackEncodeEth(0), swapData
            )
        );

        // Execute approve then execute
        bool success;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        (success,) = user.call(fallbackExecuteData);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        // Assertions
        assertTrue(success);
        assertEq(tokenA.balanceOf(user), 900 * 10 ** 18); // 1000 - 100
        assertEq(tokenB.balanceOf(user), 1095 * 10 ** 18); // 1000 + 95
        assertEq(tokenA.balanceOf(address(mockSwap)), 10100 * 10 ** 18); // 10000 + 100
        assertEq(tokenB.balanceOf(address(mockSwap)), 9905 * 10 ** 18); // 10000 - 95

        uint128 currentNonce = MockDelegate(user).nonce();
        assertEq(currentNonce, nonce + 1);

        console.log("=== Approve Then Execute Swap Gas ===");
        console.log("Total Gas Used: %s", gasUsed);
    }

    function testFallbackExecutionWithReturn() public {
        uint256 swapAmount = 100 * 10 ** 18;
        uint256 expectedOutput = 95 * 10 ** 18; // 5% slippage

        MockDelegate(user).spoof_Nonce(5000);

        uint128 nonce = MockDelegate(user).nonce();

        bytes memory swapData = abi.encodeWithSelector(
            mockSwap.mockSwap.selector, address(tokenA), address(tokenB), swapAmount, expectedOutput
        );

        // Create the approve then execute signature
        bytes memory signature = _signApproveThenExecute(
            USER_PRIVATE_KEY,
            user,
            nonce,
            uint32(block.timestamp + 86400),
            address(tokenA),
            address(mockSwap),
            swapAmount,
            address(mockSwap),
            0,
            swapData
        );

        bytes memory fallbackExecuteData = _constructFallbackCalldata(
            0x11,
            signature,
            nonce,
            uint32(block.timestamp + 86400),
            abi.encodePacked(
                address(tokenA), address(mockSwap), swapAmount, address(mockSwap), _fallbackEncodeEth(0), swapData
            )
        );

        // Execute approve then execute
        bool success;
        bytes memory result;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        (success, result) = user.call(fallbackExecuteData);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        // Assertions
        assertTrue(success);
        assertEq(tokenA.balanceOf(user), 900 * 10 ** 18); // 1000 - 100
        assertEq(tokenB.balanceOf(user), 1095 * 10 ** 18); // 1000 + 95
        assertEq(tokenA.balanceOf(address(mockSwap)), 10100 * 10 ** 18); // 10000 + 100
        assertEq(tokenB.balanceOf(address(mockSwap)), 9905 * 10 ** 18); // 10000 - 95
        uint256 returnedAmount = abi.decode(result, (uint256));
        assertEq(returnedAmount, expectedOutput);

        uint128 currentNonce = MockDelegate(user).nonce();
        assertEq(currentNonce, nonce + 1);

        console.log("=== Approve Then Execute Swap Gas ===");
        console.log("Total Gas Used: %s", gasUsed);
    }

    // ========== PARAMETERIZED VERSIONS ==========

    function testApproveThenExecuteParameterizedNoReturn_Succeeds() public {
        uint256 swapAmount = 100 * 10 ** 18;
        uint256 expectedOutput = 95 * 10 ** 18;

        uint128 nonce = MockDelegate(user).nonce();

        bytes memory swapData = abi.encodeWithSelector(
            mockSwap.mockSwap.selector, address(tokenA), address(tokenB), swapAmount, expectedOutput
        );

        bytes memory signature = _signApproveThenExecute(
            USER_PRIVATE_KEY,
            user,
            nonce,
            uint32(block.timestamp + 86400),
            address(tokenA),
            address(mockSwap),
            swapAmount,
            address(mockSwap),
            0,
            swapData
        );

        // Create data manually: [signature(65)][nonce(16)][deadline(4)][args]
        bytes memory data =
            abi.encodePacked(signature, bytes16(nonce), bytes4(uint32(block.timestamp + 86400)), swapData);

        vm.prank(paymaster);
        MockDelegate(user).approveThenExecute(
            address(mockSwap), 0, address(tokenA), address(mockSwap), swapAmount, data
        );
        vm.stopPrank();

        // Verify the swap succeeded
        assertEq(tokenA.balanceOf(user), 900 * 10 ** 18); // 1000 - 100
        assertEq(tokenB.balanceOf(user), 1095 * 10 ** 18); // 1000 + 95
        assertEq(tokenA.balanceOf(address(mockSwap)), 10100 * 10 ** 18); // 10000 + 100
        assertEq(tokenB.balanceOf(address(mockSwap)), 9905 * 10 ** 18); // 10000 - 95

        uint128 currentNonce = MockDelegate(user).nonce();
        assertEq(currentNonce, nonce + 1);
    }

    function testApproveThenExecuteParameterizedSwap() public {
        uint256 swapAmount = 100 * 10 ** 18;
        uint256 expectedOutput = 95 * 10 ** 18;

        uint128 nonce = MockDelegate(user).nonce();

        bytes memory swapData = abi.encodeWithSelector(
            mockSwap.mockSwap.selector, address(tokenA), address(tokenB), swapAmount, expectedOutput
        );

        bytes memory signature = _signApproveThenExecute(
            USER_PRIVATE_KEY,
            user,
            nonce,
            uint32(block.timestamp + 86400),
            address(tokenA),
            address(mockSwap),
            swapAmount,
            address(mockSwap),
            0,
            swapData
        );

        // Create data manually: [signature(65)][nonce(16)][args]
        bytes memory data =
            abi.encodePacked(signature, bytes16(nonce), bytes4(uint32(block.timestamp + 86400)), swapData);

        bytes memory result;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        result = MockDelegate(user).approveThenExecuteReturns(
            address(mockSwap), 0, address(tokenA), address(mockSwap), swapAmount, data
        );
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        // Success is implicit - if we get here without reverting, the call succeeded
        assertEq(tokenA.balanceOf(user), 900 * 10 ** 18); // 1000 - 100
        assertEq(tokenB.balanceOf(user), 1095 * 10 ** 18); // 1000 + 95
        assertEq(tokenA.balanceOf(address(mockSwap)), 10100 * 10 ** 18); // 10000 + 100
        assertEq(tokenB.balanceOf(address(mockSwap)), 9905 * 10 ** 18); // 10000 - 95
        uint256 returnedAmount = abi.decode(result, (uint256));
        assertEq(returnedAmount, expectedOutput);

        uint128 currentNonce = MockDelegate(user).nonce();
        assertEq(currentNonce, nonce + 1);

        console.log("=== Approve Then Execute Parameterized Swap Gas ===");
        console.log("Total Gas Used: %s", gasUsed);
    }

    function testApproveThenExecuteParameterizedSwapWithETH() public {
        uint256 swapAmount = 50 * 10 ** 18;
        uint256 expectedOutput = 47 * 10 ** 18;
        uint256 ethAmount = 0.1 ether;

        vm.deal(user, 1 ether);
        uint128 nonce = MockDelegate(user).nonce();

        bytes memory swapData = abi.encodeWithSelector(
            mockSwap.mockSwap.selector, address(tokenA), address(tokenB), swapAmount, expectedOutput
        );

        bytes memory signature = _signApproveThenExecute(
            USER_PRIVATE_KEY,
            user,
            nonce,
            uint32(block.timestamp + 86400),
            address(tokenA),
            address(mockSwap),
            swapAmount,
            address(mockSwap),
            ethAmount,
            swapData
        );

        // Create data manually: [signature(65)][nonce(16)][args]
        bytes memory data =
            abi.encodePacked(signature, bytes16(nonce), bytes4(uint32(block.timestamp + 86400)), swapData);

        bytes memory result;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        result = MockDelegate(user).approveThenExecuteReturns(
            address(mockSwap), ethAmount, address(tokenA), address(mockSwap), swapAmount, data
        );
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        // Success is implicit - if we get here without reverting, the call succeeded
        assertEq(tokenA.balanceOf(user), 950 * 10 ** 18); // 1000 - 50
        assertEq(tokenB.balanceOf(user), 1047 * 10 ** 18); // 1000 + 47
        assertEq(tokenA.balanceOf(address(mockSwap)), 10050 * 10 ** 18); // 10000 + 50
        assertEq(tokenB.balanceOf(address(mockSwap)), 9953 * 10 ** 18); // 10000 - 47
        uint256 returnedAmount = abi.decode(result, (uint256));
        assertEq(returnedAmount, expectedOutput);

        uint128 currentNonce = MockDelegate(user).nonce();
        assertEq(currentNonce, nonce + 1);

        console.log("=== Approve Then Execute Parameterized Swap With ETH Gas ===");
        console.log("Total Gas Used: %s", gasUsed);
    }

    function testApproveThenExecuteParameterizedWrongNonceReverts() public {
        uint256 swapAmount = 100 * 10 ** 18;
        uint256 expectedOutput = 95 * 10 ** 18;

        uint128 currentNonce = MockDelegate(user).nonce();
        uint128 wrongNonce = currentNonce + 1; // Use wrong nonce

        bytes memory swapData = abi.encodeWithSelector(
            mockSwap.mockSwap.selector, address(tokenA), address(tokenB), swapAmount, expectedOutput
        );

        bytes memory signature = _signApproveThenExecute(
            USER_PRIVATE_KEY,
            user,
            wrongNonce, // Wrong nonce
            uint32(block.timestamp + 86400),
            address(tokenA),
            address(mockSwap),
            swapAmount,
            address(mockSwap),
            0,
            swapData
        );

        // Create data manually: [signature(65)][nonce(16)][erc20(20)][spender(20)][approveAmount(32)][outputContract(20)][ethAmount(32)][args]
        bytes memory data = abi.encodePacked(
            signature,
            bytes16(wrongNonce),
            address(tokenA),
            address(mockSwap),
            bytes32(swapAmount),
            address(mockSwap),
            bytes32(0),
            swapData
        );

        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).approveThenExecute(
            address(mockSwap), 0, address(tokenA), address(mockSwap), swapAmount, data
        );
    }

    function testApproveThenExecuteParameterizedSignedByOtherUserRevertsNotSelf() public {
        uint256 swapAmount = 100 * 10 ** 18;
        uint256 expectedOutput = 95 * 10 ** 18;

        uint128 nonce = MockDelegate(user).nonce();

        bytes memory swapData = abi.encodeWithSelector(
            mockSwap.mockSwap.selector, address(tokenA), address(tokenB), swapAmount, expectedOutput
        );

        // Sign with USER_PRIVATE_KEY_2 instead of the user's key
        bytes memory signature = _signApproveThenExecute(
            USER_PRIVATE_KEY_2,
            user,
            nonce,
            uint32(block.timestamp + 86400),
            address(tokenA),
            address(mockSwap),
            swapAmount,
            address(mockSwap),
            0,
            swapData
        );

        // Create data manually: [signature(65)][nonce(16)][erc20(20)][spender(20)][approveAmount(32)][outputContract(20)][ethAmount(32)][args]
        bytes memory data = abi.encodePacked(
            signature,
            bytes16(nonce),
            address(tokenA),
            address(mockSwap),
            bytes32(swapAmount),
            address(mockSwap),
            bytes32(0),
            swapData
        );

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.NotSelf.selector);
        MockDelegate(user).approveThenExecute(
            address(mockSwap), 0, address(tokenA), address(mockSwap), swapAmount, data
        );
    }

    function testApproveThenExecuteParameterizedReplayNonceReverts() public {
        uint256 swapAmount = 10 * 10 ** 18;
        uint256 expectedOutput = 9 * 10 ** 18;
        uint128 nonce = MockDelegate(user).nonce();

        bytes memory swapData = abi.encodeWithSelector(
            mockSwap.mockSwap.selector, address(tokenA), address(tokenB), swapAmount, expectedOutput
        );

        bytes memory signature = _signApproveThenExecute(
            USER_PRIVATE_KEY,
            user,
            nonce,
            uint32(block.timestamp + 86400),
            address(tokenA),
            address(mockSwap),
            swapAmount,
            address(mockSwap),
            0,
            swapData
        );

        // Create data manually: [signature(65)][nonce(16)][args]
        bytes memory data =
            abi.encodePacked(signature, bytes16(nonce), bytes4(uint32(block.timestamp + 86400)), swapData);

        bytes memory result;
        // First execution succeeds
        vm.prank(paymaster);
        result = MockDelegate(user).approveThenExecuteReturns(
            address(mockSwap), 0, address(tokenA), address(mockSwap), swapAmount, data
        );
        // Success is implicit - if we get here without reverting, the call succeeded

        // Second execution with the same calldata must revert (nonce already consumed)
        vm.prank(paymaster);
        vm.expectRevert();
        MockDelegate(user).approveThenExecute(
            address(mockSwap), 0, address(tokenA), address(mockSwap), swapAmount, data
        );
    }

    function testApproveThenExecuteWithExpiredDeadlineReverts() public {
        uint256 swapAmount = 100 * 10 ** 18;
        uint256 expectedOutput = 95 * 10 ** 18;

        uint128 nonce = MockDelegate(user).nonce();
        uint32 expiredDeadline = uint32(block.timestamp - 1); // Deadline in the past

        bytes memory swapData = abi.encodeWithSelector(
            mockSwap.mockSwap.selector, address(tokenA), address(tokenB), swapAmount, expectedOutput
        );

        bytes memory signature = _signApproveThenExecute(
            USER_PRIVATE_KEY,
            user,
            nonce,
            expiredDeadline,
            address(tokenA),
            address(mockSwap),
            swapAmount,
            address(mockSwap),
            0,
            swapData
        );

        bytes memory data = abi.encodePacked(
            signature,
            bytes16(nonce),
            bytes4(expiredDeadline),
            address(tokenA),
            address(mockSwap),
            swapAmount,
            address(mockSwap),
            _fallbackEncodeEth(0),
            swapData
        );

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.DeadlineExceeded.selector);
        MockDelegate(user).approveThenExecute(data);
        vm.stopPrank();
    }

    function testApproveThenExecute_ApproveFalse_Reverts() public {
        MockERC20ApproveNotRevert badToken = new MockERC20ApproveNotRevert("Bad Token", "BAD");
        badToken.mint(user, 1000 * 10 ** 18);
        badToken.setApproveAllowed(false); // Make approve return false

        uint256 swapAmount = 100 * 10 ** 18;
        uint128 nonce = MockDelegate(user).nonce();

        bytes memory swapData = abi.encodeWithSelector(
            mockSwap.mockSwap.selector, address(badToken), address(tokenB), swapAmount, 95 * 10 ** 18
        );

        bytes memory signature = _signApproveThenExecute(
            USER_PRIVATE_KEY,
            user,
            nonce,
            uint32(block.timestamp + 86400),
            address(badToken),
            address(mockSwap),
            swapAmount,
            address(mockSwap),
            0,
            swapData
        );

        bytes memory data = _constructApproveThenExecuteBytes(
            signature,
            nonce,
            uint32(block.timestamp + 86400),
            address(badToken),
            address(mockSwap),
            swapAmount,
            address(mockSwap),
            0,
            swapData
        );

        vm.prank(paymaster);
        vm.expectRevert(bytes4(keccak256("ApprovalReturnFalse()")));
        MockDelegate(user).approveThenExecute(data);
        vm.stopPrank();
    }

    function testApproveThenExecuteParameterized_ApproveFalse_Reverts() public {
        MockERC20ApproveNotRevert badToken = new MockERC20ApproveNotRevert("Bad Token", "BAD");
        badToken.mint(user, 1000 * 10 ** 18);
        badToken.setApproveAllowed(false); // Make approve return false

        uint256 swapAmount = 100 * 10 ** 18;
        uint128 nonce = MockDelegate(user).nonce();

        bytes memory swapData = abi.encodeWithSelector(
            mockSwap.mockSwap.selector, address(badToken), address(tokenB), swapAmount, 95 * 10 ** 18
        );

        bytes memory signature = _signApproveThenExecute(
            USER_PRIVATE_KEY,
            user,
            nonce,
            uint32(block.timestamp + 86400),
            address(badToken),
            address(mockSwap),
            swapAmount,
            address(mockSwap),
            0,
            swapData
        );

        bytes memory data =
            abi.encodePacked(signature, bytes16(nonce), bytes4(uint32(block.timestamp + 86400)), swapData);

        vm.prank(paymaster);
        vm.expectRevert(bytes4(keccak256("ApprovalReturnFalse()")));
        MockDelegate(user).approveThenExecute(
            address(mockSwap), 0, address(badToken), address(mockSwap), swapAmount, data
        );
        vm.stopPrank();
    }

    function testApproveThenExecuteNoReturn_ApproveFalse_Reverts() public {
        MockERC20ApproveNotRevert badToken = new MockERC20ApproveNotRevert("Bad Token", "BAD");
        badToken.mint(user, 1000 * 10 ** 18);
        badToken.setApproveAllowed(false); // Make approve return false

        uint256 swapAmount = 100 * 10 ** 18;
        uint128 nonce = MockDelegate(user).nonce();

        bytes memory swapData = abi.encodeWithSelector(
            mockSwap.mockSwap.selector, address(badToken), address(tokenB), swapAmount, 95 * 10 ** 18
        );

        bytes memory signature = _signApproveThenExecute(
            USER_PRIVATE_KEY,
            user,
            nonce,
            uint32(block.timestamp + 86400),
            address(badToken),
            address(mockSwap),
            swapAmount,
            address(mockSwap),
            0,
            swapData
        );

        bytes memory data =
            abi.encodePacked(signature, bytes16(nonce), bytes4(uint32(block.timestamp + 86400)), swapData);

        vm.prank(paymaster);
        vm.expectRevert(bytes4(keccak256("ApprovalReturnFalse()")));
        MockDelegate(user).approveThenExecute(
            address(mockSwap), 0, address(badToken), address(mockSwap), swapAmount, data
        );
        vm.stopPrank();
    }

    function testFallbackApproveThenExecute_ApproveFalse_Reverts() public {
        MockERC20ApproveNotRevert badToken = new MockERC20ApproveNotRevert("Bad Token", "BAD");
        badToken.mint(user, 1000 * 10 ** 18);
        badToken.setApproveAllowed(false); // Make approve return false

        uint256 swapAmount = 100 * 10 ** 18;
        uint128 nonce = MockDelegate(user).nonce();

        bytes memory swapData = abi.encodeWithSelector(
            mockSwap.mockSwap.selector, address(badToken), address(tokenB), swapAmount, 95 * 10 ** 18
        );

        bytes memory signature = _signApproveThenExecute(
            USER_PRIVATE_KEY,
            user,
            nonce,
            uint32(block.timestamp + 86400),
            address(badToken),
            address(mockSwap),
            swapAmount,
            address(mockSwap),
            0,
            swapData
        );

        bytes memory fallbackData = _constructFallbackCalldata(
            bytes1(0x10), // approveThenExecute no return
            signature,
            nonce,
            uint32(block.timestamp + 86400),
            abi.encodePacked(
                address(badToken), address(mockSwap), swapAmount, address(mockSwap), _fallbackEncodeEth(0), swapData
            )
        );

        vm.prank(paymaster);
        vm.expectRevert(bytes4(keccak256("ApprovalReturnFalse()")));
        (bool success,) = address(MockDelegate(user)).call(fallbackData);
        vm.stopPrank();
    }
}
