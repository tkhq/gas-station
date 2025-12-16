// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AddressSmartWalletDelegate} from "./AddressSmartWalletDelegate.sol";
import {LibClone} from "solady/utils/LibClone.sol";

contract AddressSmartWalletFactory {
    event WalletCreated(address indexed instance, address indexed authority);

    address public immutable IMPLEMENTATION;

    constructor(address _implementation) {
        IMPLEMENTATION = _implementation;
    }

    function createWallet(address _authority) external returns (address) {
        // Encode authority as immutable argument
        bytes memory args = abi.encode(_authority);
        bytes32 salt = keccak256(args);

        // Use createDeterministicClone which doesn't revert if already deployed
        (bool alreadyDeployed, address instance) = LibClone.createDeterministicClone(IMPLEMENTATION, args, salt);
        if (!alreadyDeployed) {
            emit WalletCreated(instance, _authority);
        }
        return instance;
    }

    function createWallet(address _authority, bytes32 _salt) external returns (address) {
        // Encode authority as immutable argument
        bytes memory args = abi.encode(_authority);
        _salt = keccak256(abi.encodePacked(_salt, _authority));
        // Use createDeterministicClone which doesn't revert if already deployed
        (bool alreadyDeployed, address instance) = LibClone.createDeterministicClone(IMPLEMENTATION, args, _salt);
        if (!alreadyDeployed) {
            emit WalletCreated(instance, _authority);
        }
        return instance;
    }
}
