// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {MockBasicTKSmartWallet} from "./Mocks/MockBasicTKSmartWallet.sol";
import {MockContractInteraction} from "./Mocks/MockContractInteraction.sol";
import {BasicTKSmartWallet} from "../src/BasicTKSmartWallet.sol";

contract TKSmartWalletNoManagerTest is Test {

    MockBasicTKSmartWallet public smartWallet;
    MockContractInteraction public mockContract;
    
    // Test addresses
    address payable A_ADDRESS;
    address payable B_ADDRESS;
    // Private keys
    uint256 constant A_PRIVATE_KEY = 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a;
    uint256 constant B_PRIVATE_KEY = 0x7c852118e8d7e3bdfa4b9c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8;
    
    // Function selectors
    bytes4 constant ADD_FUNCTION = 0x1003e2d2;
    bytes4 constant SUB_FUNCTION = 0x4d2301cc;
    
    // Test values
    uint256 constant ONE = 1;
    uint256 constant ZERO = 0;
    
    // State variables
    uint64 public timeout;
    bytes4[] public emptyFunctions;
    bytes4[] public allowedFunctions;

    function setUp() public {
        A_ADDRESS = payable(vm.addr(A_PRIVATE_KEY));
        B_ADDRESS = payable(vm.addr(B_PRIVATE_KEY));
        // Deploy mock contract
        mockContract = new MockContractInteraction();
        
        // Setup function arrays
        emptyFunctions = new bytes4[](0);
        allowedFunctions = new bytes4[](1);
        allowedFunctions[0] = ADD_FUNCTION;
        
        // Deploy smart wallet without manager
        smartWallet = new MockBasicTKSmartWallet(
            address(mockContract),  // interactionContract
            false,                  // useManager = false
            emptyFunctions          // no allowed functions restriction
        );
        
        timeout = uint64(block.timestamp + 1000);

        vm.startBroadcast(A_PRIVATE_KEY);
        vm.signAndAttachDelegation(address(smartWallet), A_PRIVATE_KEY);
        MockBasicTKSmartWallet(A_ADDRESS).login(B_ADDRESS, timeout);
        vm.stopBroadcast();
    }

    function test_CreateSmartWallet() public view {
        assertEq(address(smartWallet) != address(0), true);
        assertEq(smartWallet.interactionContract(), address(mockContract));
        assertEq(smartWallet.useManager(), false);
        assertEq(smartWallet.allowedFunctions() == 0, true);
    }

    function test_execute() public {

        // Check initial state
        assertEq(mockContract.getBalance(A_ADDRESS), 0);
        assertEq(mockContract.getBalance(B_ADDRESS), 0);

        // Execute transaction
        vm.startBroadcast(B_PRIVATE_KEY);
        MockBasicTKSmartWallet(A_ADDRESS).execute(0, abi.encodeWithSelector(ADD_FUNCTION, ONE));
        vm.stopBroadcast();

        // Verify execution
        assertEq(mockContract.getBalance(A_ADDRESS), 1);
        assertEq(mockContract.getBalance(B_ADDRESS), 0);
    }
 
    function test_execute_with_eth() public {

        // Fund the smart wallet with ETH
        vm.deal(A_ADDRESS, 1 ether);
        
        assertEq(mockContract.getBalance(A_ADDRESS), 0 ether);
        assertEq(mockContract.getETHBalance(), 0);

        // Execute with ETH value
        vm.startBroadcast(B_PRIVATE_KEY);
        MockBasicTKSmartWallet(A_ADDRESS).execute(
            0.5 ether, 
            abi.encodeWithSelector(mockContract.addWithETH.selector, ONE)
        );
        vm.stopBroadcast();
        
        assertEq(mockContract.getBalance(A_ADDRESS), 1);
        assertEq(mockContract.getETHBalance(), 0.5 ether);
    }

    function test_execute_reverts_if_timeout() public {

        // Warp past timeout
        vm.warp(timeout + 1);

        // Should revert on execution
        vm.startBroadcast(B_PRIVATE_KEY);
        vm.expectRevert(abi.encodeWithSelector(BasicTKSmartWallet.ExecutorTimeout.selector));
        MockBasicTKSmartWallet(A_ADDRESS).execute(0, abi.encodeWithSelector(ADD_FUNCTION, ONE));
        vm.stopBroadcast();
    }

    function test_execute_reverts_on_logout() public {

        // Logout
        vm.startBroadcast(B_PRIVATE_KEY);
        MockBasicTKSmartWallet(A_ADDRESS).logout();
        vm.stopBroadcast();

        // Should revert on execution
        vm.startBroadcast(B_PRIVATE_KEY);
        vm.expectRevert(abi.encodeWithSelector(BasicTKSmartWallet.ExecutorNotInitialized.selector));
        MockBasicTKSmartWallet(A_ADDRESS).execute(0, abi.encodeWithSelector(ADD_FUNCTION, ONE));
        vm.stopBroadcast();
    }

    function test_executeMetaTx() public {

        // Get current nonce
        uint256 nonce = MockBasicTKSmartWallet(A_ADDRESS).getNonce();
        
        // Create execution data
        bytes memory executionData = abi.encodeWithSelector(ADD_FUNCTION, ONE);
        
        // Sign the transaction
        bytes32 hash = MockBasicTKSmartWallet(A_ADDRESS).getHash(B_ADDRESS, nonce, timeout, 0, executionData);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(B_PRIVATE_KEY, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Execute meta transaction
        MockBasicTKSmartWallet(A_ADDRESS).executeMetaTx(B_ADDRESS, nonce, timeout, 0, executionData, signature);

        // Verify execution
        assertEq(mockContract.getBalance(A_ADDRESS), 1);
        assertEq(MockBasicTKSmartWallet(A_ADDRESS).getNonce(), nonce + 1);
    }

    function test_executeMetaTx_with_eth() public {

        // Fund the smart wallet with ETH
        vm.deal(A_ADDRESS, 1 ether);

        // Get current nonce
        uint256 nonce = MockBasicTKSmartWallet(A_ADDRESS).getNonce();
        
        // Create execution data
        bytes memory executionData = abi.encodeWithSelector(mockContract.addWithETH.selector, ONE);
        
        // Sign the transaction
        bytes32 hash = MockBasicTKSmartWallet(A_ADDRESS).getHash(B_ADDRESS, nonce, timeout, 0.5 ether, executionData);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(B_PRIVATE_KEY, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Execute meta transaction
        MockBasicTKSmartWallet(A_ADDRESS).executeMetaTx(B_ADDRESS, nonce, timeout, 0.5 ether, executionData, signature);

        // Verify execution
        assertEq(mockContract.getBalance(A_ADDRESS), 1);
        assertEq(mockContract.getETHBalance(), 0.5 ether);
        assertEq(MockBasicTKSmartWallet(A_ADDRESS).getNonce(), nonce + 1);
    }

    function test_executeMetaTx_reverts_if_invalid_signature() public {

        // Get current nonce
        uint256 nonce = MockBasicTKSmartWallet(A_ADDRESS).getNonce();
        
        // Create execution data
        bytes memory executionData = abi.encodeWithSelector(ADD_FUNCTION, ONE);
        
        // Sign with wrong private key
        bytes32 hash = MockBasicTKSmartWallet(A_ADDRESS).getHash(B_ADDRESS, nonce, timeout, 0, executionData);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(A_PRIVATE_KEY, hash); // Wrong signer
        bytes memory signature = abi.encodePacked(r, s, v);

        // Should revert on invalid signature
        vm.expectRevert(abi.encodeWithSelector(BasicTKSmartWallet.InvalidSignature.selector));
        MockBasicTKSmartWallet(A_ADDRESS).executeMetaTx(B_ADDRESS, nonce, timeout, 0, executionData, signature);
    }

    function test_executeMetaTx_reverts_if_invalid_nonce() public {

        // Use wrong nonce
        uint256 wrongNonce = 999;
        
        // Create execution data
        bytes memory executionData = abi.encodeWithSelector(ADD_FUNCTION, ONE);
        
        // Sign the transaction
        bytes32 hash = MockBasicTKSmartWallet(A_ADDRESS).getHash(B_ADDRESS, wrongNonce, timeout, 0, executionData);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(B_PRIVATE_KEY, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Should revert on invalid nonce
        vm.expectRevert(abi.encodeWithSelector(BasicTKSmartWallet.InvalidNonce.selector));
        MockBasicTKSmartWallet(A_ADDRESS).executeMetaTx(B_ADDRESS, wrongNonce, timeout, 0, executionData, signature);
    }

    function test_allowed_functions_restriction() public {
        // Deploy smart wallet with function restrictions
        MockBasicTKSmartWallet restrictedWallet = new MockBasicTKSmartWallet(
            address(mockContract),
            false,                  // useManager = false
            allowedFunctions        // only ADD_FUNCTION allowed
        );

        // Setup delegation and login
        vm.startBroadcast(A_PRIVATE_KEY);
        vm.signAndAttachDelegation(address(restrictedWallet), A_PRIVATE_KEY);
        MockBasicTKSmartWallet(A_ADDRESS).login(B_ADDRESS, timeout);
        vm.stopBroadcast();

        // Test allowed function
        vm.startBroadcast(B_PRIVATE_KEY);
        MockBasicTKSmartWallet(A_ADDRESS).execute(0, abi.encodeWithSelector(ADD_FUNCTION, ONE));
        vm.stopBroadcast();
        assertEq(mockContract.getBalance(A_ADDRESS), 1);

        // Test disallowed function
        vm.startBroadcast(B_PRIVATE_KEY);
        vm.expectRevert(abi.encodeWithSelector(BasicTKSmartWallet.FunctionNotAllowed.selector));
        MockBasicTKSmartWallet(A_ADDRESS).execute(0, abi.encodeWithSelector(SUB_FUNCTION, ONE));
        vm.stopBroadcast();
    }
} 