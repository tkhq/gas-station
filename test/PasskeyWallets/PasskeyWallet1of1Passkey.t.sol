// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {TKSmartWalletFactory} from "../../src/TKGasStation/TKSmartWallet/TKSmartWalletFactory.sol";
import {TKSmartWalletGasStation} from "../../src/TKGasStation/TKSmartWallet/TKSmartWalletGasStation.sol";
import {ITKGasDelegate} from "../../src/TKGasStation/interfaces/ITKGasDelegate.sol";
import {MockERC20} from "../mocks/MockERC20.t.sol";

contract PasskeyWallet1of1PasskeyTest is Test {
    TKSmartWalletFactory internal factory;
    TKSmartWalletGasStation internal gasStation;
    MockERC20 internal mockToken;

    bytes32 internal publicKeyX;
    bytes32 internal publicKeyY;
    address internal wallet;
    address internal constant P256_VERIFY = address(0x100);

    function setUp() public {
        // Deploy factory and gas station
        factory = new TKSmartWalletFactory();
        address delegateImplementation = factory.IMPLEMENTATION();
        gasStation = new TKSmartWalletGasStation(delegateImplementation);

        // Deploy mock ERC20
        mockToken = new MockERC20("Test Token", "TEST");

        // Set up passkey public key (using test values)
        publicKeyX = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        publicKeyY = 0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321;

        // Create wallet from public key
        wallet = factory.createWallet(publicKeyX, publicKeyY);

        // Mint tokens to the wallet
        mockToken.mint(wallet, 100 * 10 ** 18);

        // Mock the P256_VERIFY precompile at 0x100 because:
        // 1. The RIP-7212 precompile is not available in Foundry's default test environment
        // 2. Even if available, we'd need actual P-256 signatures which complicates testing
        // 3. This allows us to test the integration flow without real cryptographic signatures
        _mockP256Verify(true);
    }

    function _mockP256Verify(bool shouldSucceed) internal {
        // Use Solady's passthrough bytecode pattern to mock the precompile
        // Bytecode: PUSH1 0x01 (or 0x00), PUSH1 0x00, MSTORE, PUSH1 0x20, PUSH1 0x00, RETURN
        // This returns 1 (success) or 0 (failure) in 32 bytes
        bytes memory code;
        if (shouldSucceed) {
            code = hex"600160005260206000f3"; // Returns 1 (success)
        } else {
            code = hex"600060005260206000f3"; // Returns 0 (failure)
        }
        vm.etch(P256_VERIFY, code);
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

        // Create a mock passkey signature (64 bytes: r and s)
        // In reality, this would be a valid P-256 signature, but for testing we'll use mock values
        bytes32 r = keccak256(abi.encodePacked("r", hash, nonce));
        bytes32 s = keccak256(abi.encodePacked("s", hash, nonce));
        bytes memory signature = abi.encodePacked(r, s, bytes1(0)); // 65 bytes total

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

        // Create a mock passkey signature
        bytes32 r = keccak256(abi.encodePacked("r", hash, nonce));
        bytes32 s = keccak256(abi.encodePacked("s", hash, nonce));
        bytes memory signature = abi.encodePacked(r, s, bytes1(0)); // 65 bytes total

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

        // Mock P256_VERIFY to return failure (invalid signature)
        _mockP256Verify(false);

        // Create a mock passkey signature (will fail validation)
        bytes32 r = keccak256(abi.encodePacked("r", hash, nonce));
        bytes32 s = keccak256(abi.encodePacked("s", hash, nonce));
        bytes memory signature = abi.encodePacked(r, s, bytes1(0)); // 65 bytes total

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

        // Create a mock passkey signature
        bytes32 r = keccak256(abi.encodePacked("r", hash, nonce));
        bytes32 s = keccak256(abi.encodePacked("s", hash, nonce));
        bytes memory signature = abi.encodePacked(r, s, bytes1(0)); // 65 bytes total

        // Build the execute data
        bytes memory executeData = abi.encodePacked(signature, bytes16(nonce), bytes4(deadline), args);

        // Execution should fail due to expired deadline
        vm.expectRevert();
        gasStation.executeReturns(wallet, address(mockToken), 0, executeData);
    }

    function testWalletCreatedFromPublicKey() public view {
        // Verify wallet was created correctly
        address retrieved = factory.getAddressForPublicKey(publicKeyX, publicKeyY);
        assertEq(wallet, retrieved);
        assertNotEq(wallet, address(0));
    }
}

