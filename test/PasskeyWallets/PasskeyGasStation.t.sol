// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {PasskeyFactory} from "../../src/TKGasStation/PasskeyWallets/PasskeyFactory.sol";
import {PasskeyGasStation} from "../../src/TKGasStation/PasskeyWallets/PasskeyGasStation.sol";

contract PasskeyGasStationTest is Test {
    PasskeyFactory internal passkeyFactory;
    PasskeyGasStation internal passkeyGasStation;

    address internal eoaOwner;

    function setUp() public {
        // Deploy the factory and derive the delegate implementation just like the deploy script.
        passkeyFactory = new PasskeyFactory();
        address delegateImplementation = passkeyFactory.IMPLEMENTATION();

        // Deploy the PasskeyGasStation pointing at the delegate implementation.
        passkeyGasStation = new PasskeyGasStation(delegateImplementation);

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


