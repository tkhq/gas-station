// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {AddressSmartWalletFactory} from "../../src/TKGasStation/TKSmartWallet/Immutable/Address/AddressSmartWalletFactory.sol";
import {AddressSmartWalletDelegate} from "../../src/TKGasStation/TKSmartWallet/Immutable/Address/AddressSmartWalletDelegate.sol";
import {ImmutableSmartWalletGasStation} from "../../src/TKGasStation/TKSmartWallet/Immutable/ImmutableSmartWalletGasStation.sol";

contract AddressFactoryTest is Test {
    AddressSmartWalletFactory internal factory;

    ImmutableSmartWalletGasStation internal gasStation;


    function setUp() public {
        // Deploy the delegate implementation first
        AddressSmartWalletDelegate delegateImpl = new AddressSmartWalletDelegate();
        // Deploy the factory with the implementation
        factory = new AddressSmartWalletFactory(address(delegateImpl));
        gasStation = new ImmutableSmartWalletGasStation(address(delegateImpl), 77);
    }

    function testCreateAddressWallet() public {
        address authority = address(0x1234567890123456789012345678901234567890);
        address wallet = factory.createWallet(authority);
        console2.logBytes(abi.encodePacked(factory.IMPLEMENTATION()));
        console2.logBytes(wallet.code);
        assertNotEq(wallet, address(0), "Wallet should be deployed");
        assertGt(wallet.code.length, 0, "Wallet should have code");
        assertEq(wallet.code.length, 77, "Wallet should be a minimal proxy with immutable args (77 bytes)");
        
        // Print the bytecode

        AddressSmartWalletDelegate delegate = AddressSmartWalletDelegate(payable(wallet));
        address storedAuthority = delegate.getAuthority();
        assertEq(storedAuthority, authority, "Authority should be correct");

        assertEq(gasStation.isDelegated(wallet), true, "Wallet should be delegated");

        assertEq(gasStation.getNonce(wallet), 0, "Wallet should have a nonce of 0");

        assertEq(gasStation.getNonce(wallet, 0), 0, "Wallet should have a nonce of 0");
    }

}
