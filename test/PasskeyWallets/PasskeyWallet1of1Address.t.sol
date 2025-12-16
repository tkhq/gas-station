// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {TKSmartWalletFactory} from "../../src/TKGasStation/TKSmartWallet/TKSmartWalletFactory.sol";
import {TKSmartWalletGasStation} from "../../src/TKGasStation/TKSmartWallet/TKSmartWalletGasStation.sol";
import {ITKGasDelegate} from "../../src/TKGasStation/interfaces/ITKGasDelegate.sol";
import {MockERC20} from "../mocks/MockERC20.t.sol";

contract PasskeyWallet1of1AddressTest is Test {
    TKSmartWalletFactory internal factory;
    TKSmartWalletGasStation internal gasStation;
    MockERC20 internal mockToken;

    address internal eoaOwner;
    uint256 internal constant OWNER_PRIVATE_KEY = 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA;
    address internal wallet;

    function setUp() public {
        // Deploy factory and gas station
        factory = new TKSmartWalletFactory();
        address delegateImplementation = factory.IMPLEMENTATION();
        gasStation = new TKSmartWalletGasStation(delegateImplementation);

        // Deploy mock ERC20
        mockToken = new MockERC20("Test Token", "TEST");

        // Set up EOA owner
        eoaOwner = vm.addr(OWNER_PRIVATE_KEY);

        // Create wallet from address
        wallet = factory.createWallet(eoaOwner);

        // Mint tokens to the wallet
        mockToken.mint(wallet, 100 * 10 ** 18);
    }

    function testExecuteERC20Transfer() public {
        address receiver = makeAddr("receiver");
        uint256 transferAmount = 50 * 10 ** 18;

        // Get current nonce from the wallet
        uint128 nonce = ITKGasDelegate(wallet).nonce();
        uint32 deadline = uint32(block.timestamp + 86400);

        // Prepare the transfer arguments
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, transferAmount);

        // Create the execution hash
        bytes32 hash = ITKGasDelegate(wallet).hashExecution(nonce, deadline, address(mockToken), 0, args);

        // Sign the hash with the owner's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PRIVATE_KEY, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Build the execute data: signature(65) + nonce(16) + deadline(4) + args
        bytes memory executeData = abi.encodePacked(signature, bytes16(nonce), bytes4(deadline), args);

        // Execute the transaction through the gas station
        bytes memory result = gasStation.executeReturns(wallet, address(mockToken), 0, executeData);

        // Verify the transfer succeeded
        assertEq(mockToken.balanceOf(receiver), transferAmount);
        assertEq(mockToken.balanceOf(wallet), 100 * 10 ** 18 - transferAmount);
        assertTrue(abi.decode(result, (bool)));
    }

    function testExecuteERC20TransferNoReturn() public {
        address receiver = makeAddr("receiver2");
        uint256 transferAmount = 25 * 10 ** 18;

        // Get current nonce from the wallet
        uint128 nonce = ITKGasDelegate(wallet).nonce();
        uint32 deadline = uint32(block.timestamp + 86400);

        // Prepare the transfer arguments
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, transferAmount);

        // Create the execution hash
        bytes32 hash = ITKGasDelegate(wallet).hashExecution(nonce, deadline, address(mockToken), 0, args);

        // Sign the hash with the owner's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PRIVATE_KEY, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Build the execute data: signature(65) + nonce(16) + deadline(4) + args
        bytes memory executeData = abi.encodePacked(signature, bytes16(nonce), bytes4(deadline), args);

        // Execute the transaction through the gas station (no return version)
        gasStation.execute(wallet, address(mockToken), 0, executeData);

        // Verify the transfer succeeded
        assertEq(mockToken.balanceOf(receiver), transferAmount);
        assertEq(mockToken.balanceOf(wallet), 100 * 10 ** 18 - transferAmount);
    }

    function testExecuteWithInvalidSignature() public {
        address receiver = makeAddr("receiver3");
        uint256 transferAmount = 10 * 10 ** 18;

        // Get current nonce from the wallet
        uint128 nonce = ITKGasDelegate(wallet).nonce();
        uint32 deadline = uint32(block.timestamp + 86400);

        // Prepare the transfer arguments
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, transferAmount);

        // Create the execution hash
        bytes32 hash = ITKGasDelegate(wallet).hashExecution(nonce, deadline, address(mockToken), 0, args);

        // Sign with a different private key (invalid signature)
        uint256 wrongPrivateKey = 0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPrivateKey, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Build the execute data
        bytes memory executeData = abi.encodePacked(signature, bytes16(nonce), bytes4(deadline), args);

        // Execution should fail due to invalid signature
        vm.expectRevert();
        gasStation.executeReturns(wallet, address(mockToken), 0, executeData);
    }

    function testExecuteWithExpiredDeadline() public {
        address receiver = makeAddr("receiver4");
        uint256 transferAmount = 10 * 10 ** 18;

        // Get current nonce from the wallet
        uint128 nonce = ITKGasDelegate(wallet).nonce();
        uint32 deadline = uint32(block.timestamp - 1); // Expired deadline

        // Prepare the transfer arguments
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, transferAmount);

        // Create the execution hash
        bytes32 hash = ITKGasDelegate(wallet).hashExecution(nonce, deadline, address(mockToken), 0, args);

        // Sign the hash with the owner's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PRIVATE_KEY, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Build the execute data
        bytes memory executeData = abi.encodePacked(signature, bytes16(nonce), bytes4(deadline), args);

        // Execution should fail due to expired deadline
        vm.expectRevert();
        gasStation.executeReturns(wallet, address(mockToken), 0, executeData);
    }
}

