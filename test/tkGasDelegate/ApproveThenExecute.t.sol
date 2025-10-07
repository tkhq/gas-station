// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {MockDelegate} from "../mocks/MockDelegate.t.sol";
import {MockERC20} from "../mocks/MockERC20.t.sol";
import {MockContractInteractions} from "../mocks/MockContractInteractions.t.sol";
import {TKGasDelegateTestBase} from "./TKGasDelegateTestBase.t.sol";

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
        
        (, uint128 nonce) = MockDelegate(user).state();
        
        bytes memory swapData = abi.encodeWithSelector(
            mockSwap.mockSwap.selector,
            address(tokenA),
            address(tokenB),
            swapAmount,
            expectedOutput
        );
        
        // Create the approve then execute signature
        bytes memory signature = _signApproveThenExecute(
            USER_PRIVATE_KEY,
            user,
            nonce,
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
            address(tokenA),
            address(mockSwap),
            swapAmount,
            address(mockSwap),
            0,
            swapData
        );
        
        // Execute approve then execute
        bool success;
        bytes memory result;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        (success, result) = MockDelegate(user).approveThenExecute(executeData);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();
        
        // Assertions
        assertTrue(success);
        assertEq(tokenA.balanceOf(user), 900 * 10 ** 18); // 1000 - 100
        assertEq(tokenB.balanceOf(user), 1095 * 10 ** 18); // 1000 + 95
        assertEq(tokenA.balanceOf(address(mockSwap)), 10100 * 10 ** 18); // 10000 + 100
        assertEq(tokenB.balanceOf(address(mockSwap)), 9905 * 10 ** 18); // 10000 - 95
        
        (, uint128 currentNonce) = MockDelegate(user).state();
        assertEq(currentNonce, nonce + 1);
        
        console.log("=== Approve Then Execute Swap Gas ===");
        console.log("Total Gas Used: %s", gasUsed);
    }
    
    function testApproveThenExecuteSwapWithETH() public { // silly test, might not be needed 
        uint256 swapAmount = 50 * 10 ** 18;
        uint256 ethAmount = 0.1 ether;
        uint256 expectedOutput = 47 * 10 ** 18; // 6% slippage
        
        // Fund the user with ETH
        vm.deal(user, 1 ether);
        
        (, uint128 nonce) = MockDelegate(user).state();
        
        bytes memory swapData = abi.encodeWithSelector(
            mockSwap.mockSwap.selector,
            address(tokenA),
            address(tokenB),
            swapAmount,
            expectedOutput
        );
        
        // Create the approve then execute signature with ETH
        bytes memory signature = _signApproveThenExecute(
            USER_PRIVATE_KEY,
            user,
            nonce,
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
            address(tokenA),
            address(mockSwap),
            swapAmount,
            address(mockSwap),
            ethAmount,
            swapData
        );
        
        // Execute approve then execute with ETH
        bool success;
        bytes memory result;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        (success, result) = MockDelegate(user).approveThenExecute(executeData);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();
        
        // Assertions
        assertTrue(success);
        assertEq(tokenA.balanceOf(user), 950 * 10 ** 18); // 1000 - 50
        assertEq(tokenB.balanceOf(user), 1047 * 10 ** 18); // 1000 + 47
        assertEq(tokenA.balanceOf(address(mockSwap)), 10050 * 10 ** 18); // 10000 + 50
        assertEq(tokenB.balanceOf(address(mockSwap)), 9953 * 10 ** 18); // 10000 - 47
        
        (, uint128 currentNonce) = MockDelegate(user).state();
        assertEq(currentNonce, nonce + 1);
        
        console.log("=== Approve Then Execute Swap with ETH Gas ===");
        console.log("Total Gas Used: %s", gasUsed);
    }
}
