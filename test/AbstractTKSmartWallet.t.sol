// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test, console} from "forge-std/Test.sol";
import {MockTKSmartWallet} from "./mocks/MockTKSmartWallet.sol";
import {MockContractInteraction} from "./mocks/MockContractInteraction.sol";

// Import VmSafe to access the SignedDelegation struct
import {VmSafe} from "forge-std/Vm.sol";

contract AbstractTKSmartWalletTest is Test {
    MockTKSmartWallet public mockWallet;
    MockContractInteraction public mockContract;

    address public constant OWNER = address(0x1);
    address public constant USER2 = address(0x2);

    uint256 public constant A_PRIVATE_KEY = 0xAAAAAA;
    uint256 public constant B_PRIVATE_KEY = 0xBBBBBB;
    address public A_ADDRESS;  
    address public B_ADDRESS;  

    function setUp() public {
        mockWallet = new MockTKSmartWallet();
        mockContract = new MockContractInteraction();
        mockWallet.initialize(address(mockContract), OWNER, new bytes4[](0));
        A_ADDRESS = vm.addr(A_PRIVATE_KEY);
        B_ADDRESS = vm.addr(B_PRIVATE_KEY);
    }

    function test_CreateMockWallet() public {
        assertEq(address(mockWallet) != address(0), true);
        console.log("MockTKSmartWallet deployed at:", address(mockWallet));
        
        // Create a signed delegation using the vm
        VmSafe.SignedDelegation memory signedDelegation = vm.signDelegation(address(mockWallet), A_PRIVATE_KEY);
 
        vm.broadcast(A_PRIVATE_KEY);
        vm.attachDelegation(signedDelegation);
 
        bytes memory code = address(A_ADDRESS).code;
        require(code.length > 0, "no code written to A");
    }
} 