// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "forge-std/console2.sol";

import {PasskeySmartWalletFactory} from "../src/TKGasStation/TKSmartWallet/Immutable/Passkey/PasskeySmartWalletFactory.sol";
import {PasskeySmartWalletDelegate} from "../src/TKGasStation/TKSmartWallet/Immutable/Passkey/PasskeySmartWalletDelegate.sol";
import {AddressSmartWalletFactory} from "../src/TKGasStation/TKSmartWallet/Immutable/Address/AddressSmartWalletFactory.sol";
import {AddressSmartWalletDelegate} from "../src/TKGasStation/TKSmartWallet/Immutable/Address/AddressSmartWalletDelegate.sol";
import {ImmutableSmartWalletGasStation} from "../src/TKGasStation/TKSmartWallet/Immutable/ImmutableSmartWalletGasStation.sol";

interface IImmutableCreate2Factory {
    function safeCreate2(bytes32 _salt, bytes calldata _initCode)
        external
        payable
        returns (address _deploymentAddress);
}

/// @notice Deploys TKSmartWalletFactory and a TKGasStation wired to its implementation, on Base or any configured chain.
contract DeployImmutableSmartWallets is Script {
    address private constant IMMUTABLE_CREATE2_FACTORY = 0x0000000000FFe8B47B3e2130213B802212439497;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000004761737379; // "Gassy"
        IImmutableCreate2Factory create2Factory = IImmutableCreate2Factory(IMMUTABLE_CREATE2_FACTORY);

        // Deploy PasskeySmartWalletDelegate implementation
        bytes memory passkeyDelegateCreationCode = type(PasskeySmartWalletDelegate).creationCode;
        address passkeyDelegateImplementation = create2Factory.safeCreate2(salt, passkeyDelegateCreationCode);
        console2.log("PasskeySmartWalletDelegate deployed at:", passkeyDelegateImplementation);

        // Deploy PasskeySmartWalletFactory with the delegate implementation as constructor arg
        bytes memory passkeyFactoryCreationCode = type(PasskeySmartWalletFactory).creationCode;
        bytes memory passkeyFactoryConstructorArgs = abi.encode(passkeyDelegateImplementation);
        bytes memory passkeyFactoryInitCode = abi.encodePacked(passkeyFactoryCreationCode, passkeyFactoryConstructorArgs);
        address passkeySmartWalletFactory = create2Factory.safeCreate2(salt, passkeyFactoryInitCode);
        console2.log("PasskeySmartWalletFactory deployed at:", passkeySmartWalletFactory);

        // Deploy ImmutableSmartWalletGasStation for Passkey (109 bytes: 45 base + 64 for x and y)
        bytes memory passkeyGasStationCreationCode = type(ImmutableSmartWalletGasStation).creationCode;
        bytes memory passkeyGasStationConstructorArgs = abi.encode(passkeyDelegateImplementation, 109);
        bytes memory passkeyGasStationInitCode = abi.encodePacked(passkeyGasStationCreationCode, passkeyGasStationConstructorArgs);
        address passkeyGasStation = create2Factory.safeCreate2(salt, passkeyGasStationInitCode);
        console2.log("Passkey ImmutableSmartWalletGasStation deployed at:", passkeyGasStation);

        // Deploy AddressSmartWalletDelegate implementation
        bytes memory addressDelegateCreationCode = type(AddressSmartWalletDelegate).creationCode;
        address addressDelegateImplementation = create2Factory.safeCreate2(salt, addressDelegateCreationCode);
        console2.log("AddressSmartWalletDelegate deployed at:", addressDelegateImplementation);

        // Deploy AddressSmartWalletFactory with the delegate implementation as constructor arg
        bytes memory addressFactoryCreationCode = type(AddressSmartWalletFactory).creationCode;
        bytes memory addressFactoryConstructorArgs = abi.encode(addressDelegateImplementation);
        bytes memory addressFactoryInitCode = abi.encodePacked(addressFactoryCreationCode, addressFactoryConstructorArgs);
        address addressSmartWalletFactory = create2Factory.safeCreate2(salt, addressFactoryInitCode);
        console2.log("AddressSmartWalletFactory deployed at:", addressSmartWalletFactory);

        // Deploy ImmutableSmartWalletGasStation for Address (77 bytes: 45 base + 32 for address)
        bytes memory addressGasStationCreationCode = type(ImmutableSmartWalletGasStation).creationCode;
        bytes memory addressGasStationConstructorArgs = abi.encode(addressDelegateImplementation, 77);
        bytes memory addressGasStationInitCode = abi.encodePacked(addressGasStationCreationCode, addressGasStationConstructorArgs);
        address addressGasStation = create2Factory.safeCreate2(salt, addressGasStationInitCode);
        console2.log("Address ImmutableSmartWalletGasStation deployed at:", addressGasStation);

        vm.stopBroadcast();
    }
}
