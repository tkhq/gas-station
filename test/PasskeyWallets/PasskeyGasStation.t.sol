// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {TKSmartWalletFactory} from "../../src/TKGasStation/TKSmartWallet/TKSmartWalletFactory.sol";
import {TKSmartWalletGasStation} from "../../src/TKGasStation/TKSmartWallet/TKSmartWalletGasStation.sol";

contract PasskeyGasStationTest is Test {
    TKSmartWalletFactory internal passkeyFactory;
    TKSmartWalletGasStation internal passkeyGasStation;

    address internal eoaOwner;

    function setUp() public {
        // Deploy the factory and derive the delegate implementation just like the deploy script.
        passkeyFactory = new TKSmartWalletFactory();
        address delegateImplementation = passkeyFactory.IMPLEMENTATION();

        // Deploy the TKSmartWalletGasStation pointing at the delegate implementation.
        passkeyGasStation = new TKSmartWalletGasStation(delegateImplementation);

        eoaOwner = makeAddr("eoaOwner");
    }

    function testIsDelegatedWithFactoryWallet() public {
        // Create a wallet via the factory using the EOA address variant.
        vm.prank(eoaOwner);
        address wallet = passkeyFactory.createWallet(eoaOwner);

        // The created wallet is a minimal proxy pointing at IMPLEMENTATION,
        // so PasskeyGasStation._isDelegated should treat it as delegated.
        bool isDelegated = passkeyGasStation.isDelegated(wallet);
        assertTrue(isDelegated, "factory-created wallet should be delegated");
    }

    function testIsDelegatedFalseForPlainEOA() public {
        // A plain EOA (no code) must not be considered delegated.
        assertFalse(passkeyGasStation.isDelegated(eoaOwner), "plain EOA must not be delegated");
    }
}


