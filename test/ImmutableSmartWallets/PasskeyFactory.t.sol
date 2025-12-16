// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {PasskeySmartWalletFactory} from "../../src/TKGasStation/TKSmartWallet/Immutable/Passkey/PasskeySmartWalletFactory.sol";
import {PasskeySmartWalletDelegate} from "../../src/TKGasStation/TKSmartWallet/Immutable/Passkey/PasskeySmartWalletDelegate.sol";
import {ImmutableSmartWalletGasStation} from "../../src/TKGasStation/TKSmartWallet/Immutable/ImmutableSmartWalletGasStation.sol";

contract PasskeyFactoryTest is Test {
    PasskeySmartWalletFactory internal factory;

    ImmutableSmartWalletGasStation internal gasStation;


    function setUp() public {
        // Deploy the delegate implementation first
        PasskeySmartWalletDelegate delegateImpl = new PasskeySmartWalletDelegate();
        // Deploy the factory with the implementation
        factory = new PasskeySmartWalletFactory(address(delegateImpl));
        gasStation = new ImmutableSmartWalletGasStation(address(delegateImpl), 109);
    }

    function testCreatePasskeyWallet() public {
        address wallet = factory.createWallet(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, 0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb);
        assertNotEq(wallet, address(0), "Wallet should be deployed");
        assertGt(wallet.code.length, 0, "Wallet should have code");
        // With immutable args: 45 bytes (minimal proxy) + 64 bytes (x and y) = 109 bytes
        assertEq(wallet.code.length, 109, "Wallet should be a minimal proxy with immutable args (109 bytes)");
        
        // Print the bytecode

        PasskeySmartWalletDelegate delegate = PasskeySmartWalletDelegate(payable(wallet));
        (bytes32 x, bytes32 y) = delegate.getPublicKey();
        assertEq(x, 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, "X should be correct");
        assertEq(y, 0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb, "Y should be correct");

        assertEq(gasStation.isDelegated(wallet), true, "Wallet should be delegated");

        assertEq(gasStation.getNonce(wallet), 0, "Wallet should have a nonce of 0");

        assertEq(gasStation.getNonce(wallet, 0), 0, "Wallet should have a nonce of 0");
        
    }

}
