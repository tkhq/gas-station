// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {TKSmartWalletFactory} from "../../src/TKGasStation/TKSmartWallet/TKSmartWalletFactory.sol";
import {PublicKey} from "../../src/TKGasStation/structs/PublicKey.sol";

contract PasskeyFactoryTest is Test {
    TKSmartWalletFactory internal factory;

    function setUp() public {
        factory = new TKSmartWalletFactory();
    }

    function testCreateWalletFromPublicKey() public {
        bytes32 x = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        bytes32 y = 0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321;

        address wallet = factory.createWallet(x, y);

        // Wallet should be deployed
        assertNotEq(wallet, address(0));

        // Should be able to predict the address
        address predicted = factory.predictWalletAddress(x, y);
        assertEq(wallet, predicted);

        // Should be able to retrieve wallet from public key
        address retrieved = factory.getAddressForPublicKey(x, y);
        assertEq(wallet, retrieved);

        // Check rule set - public mapping getter returns (mOf, n) tuple
        (uint8 mOf, uint8 n) = factory.ruleSets(wallet);
        assertEq(mOf, 1);
        assertEq(n, 1);
        
        // Verify the wallet was created correctly
        assertEq(factory.getAddressForPublicKey(x, y), wallet);
    }

    function testCreateWalletFromAddress() public {
        address eoa = makeAddr("testEOA");

        address wallet = factory.createWallet(eoa);

        // Wallet should be deployed
        assertNotEq(wallet, address(0));

        // Should be able to retrieve wallet from address
        address retrieved = factory.getAddressForAddress(eoa);
        assertEq(wallet, retrieved);

        // Check rule set - public mapping getter returns (mOf, n) tuple
        (uint8 mOf, uint8 n) = factory.ruleSets(wallet);
        assertEq(mOf, 1);
        assertEq(n, 1);
        
        // Verify the wallet was created correctly
        assertEq(factory.getAddressForAddress(eoa), wallet);
    }

    function testCreateWalletWithRuleSet() public {
        bytes32 x1 = 0x1111111111111111111111111111111111111111111111111111111111111111;
        bytes32 y1 = 0x2222222222222222222222222222222222222222222222222222222222222222;
        bytes32 x2 = 0x3333333333333333333333333333333333333333333333333333333333333333;
        bytes32 y2 = 0x4444444444444444444444444444444444444444444444444444444444444444;

        address addr1 = makeAddr("addr1");
        address addr2 = makeAddr("addr2");

        PublicKey[] memory publicKeys = new PublicKey[](2);
        publicKeys[0] = PublicKey({x: x1, y: y1});
        publicKeys[1] = PublicKey({x: x2, y: y2});

        address[] memory addresses = new address[](2);
        addresses[0] = addr1;
        addresses[1] = addr2;

        uint8 mOf = 2;
        bytes32 salt = keccak256("testSalt");

        address wallet = factory.createWallet(mOf, publicKeys, addresses, salt);

        // Wallet should be deployed
        assertNotEq(wallet, address(0));

        // Check rule set - public mapping getter returns (mOf, n) tuple
        (uint8 actualMOf, uint8 actualN) = factory.ruleSets(wallet);
        assertEq(actualMOf, mOf);
        assertEq(actualN, 4); // 2 public keys + 2 addresses
        
        // Note: Dynamic arrays in structs can't be accessed directly via public getters
        // The rule set is verified by the successful creation and deterministic address
    }

    function testCreateWalletDeterministic() public {
        bytes32 x = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;
        bytes32 y = 0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb;

        // Create wallet first time
        address wallet1 = factory.createWallet(x, y);
        assertNotEq(wallet1, address(0));

        // Second creation with same public key should revert (already deployed)
        vm.expectRevert();
        factory.createWallet(x, y);
    }

    function testCreateWalletFromAddressDeterministic() public {
        address eoa = makeAddr("deterministicEOA");

        // Create wallet first time
        address wallet1 = factory.createWallet(eoa);
        assertNotEq(wallet1, address(0));

        // Second creation with same address should revert (already deployed)
        vm.expectRevert();
        factory.createWallet(eoa);
    }

    function testCreateWalletWithRuleSetDeterministic() public {
        PublicKey[] memory publicKeys = new PublicKey[](1);
        publicKeys[0] = PublicKey({
            x: 0x1111111111111111111111111111111111111111111111111111111111111111,
            y: 0x2222222222222222222222222222222222222222222222222222222222222222
        });

        address[] memory addresses = new address[](0);
        bytes32 salt = keccak256("deterministicSalt");

        // Create wallet first time
        address wallet1 = factory.createWallet(1, publicKeys, addresses, salt);
        assertNotEq(wallet1, address(0));

        // Second creation with same salt should revert (already deployed)
        vm.expectRevert();
        factory.createWallet(1, publicKeys, addresses, salt);
    }

    function testCreateWalletWithInvalidMOf() public {
        PublicKey[] memory publicKeys = new PublicKey[](1);
        publicKeys[0] = PublicKey({
            x: 0x1111111111111111111111111111111111111111111111111111111111111111,
            y: 0x2222222222222222222222222222222222222222222222222222222222222222
        });

        address[] memory addresses = new address[](0);
        bytes32 salt = keccak256("testSalt");

        // mOf > n should revert
        vm.expectRevert(TKSmartWalletFactory.InvalidMOf.selector);
        factory.createWallet(2, publicKeys, addresses, salt);

        // mOf == 0 should revert
        vm.expectRevert(TKSmartWalletFactory.InvalidMOf.selector);
        factory.createWallet(0, publicKeys, addresses, salt);
    }


    function testCreateWalletWithEmptyArrays() public {
        PublicKey[] memory publicKeys = new PublicKey[](0);
        address[] memory addresses = new address[](0);
        bytes32 salt = keccak256("testSalt");

        // n == 0 should revert
        vm.expectRevert(TKSmartWalletFactory.InvalidN.selector);
        factory.createWallet(1, publicKeys, addresses, salt);
    }

    function testCreateWalletWithArrayLengthTooLarge() public {
        PublicKey[] memory publicKeys = new PublicKey[](128);
        address[] memory addresses = new address[](0);
        bytes32 salt = keccak256("testSalt");

        // Array length > MAX_ARRAY_LENGTH should revert
        vm.expectRevert(TKSmartWalletFactory.InvalidArrayLength.selector);
        factory.createWallet(1, publicKeys, addresses, salt);
    }

    function testGetImplementation() public view {
        address implementation = factory.IMPLEMENTATION();
        assertNotEq(implementation, address(0));
    }

    function testInitCodeHash() public view {
        bytes32 hash = factory.initCodeHash();
        assertNotEq(hash, bytes32(0));
    }
}
