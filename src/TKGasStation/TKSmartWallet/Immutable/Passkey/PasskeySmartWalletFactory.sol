// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {PasskeySmartWalletDelegate} from "./PasskeySmartWalletDelegate.sol";
import {LibClone} from "solady/utils/LibClone.sol";

contract PasskeySmartWalletFactory {

    event WalletCreated(address indexed instance, bytes32 x, bytes32 y);

    address public immutable IMPLEMENTATION;

    constructor(address _implementation) {
        IMPLEMENTATION = _implementation;
    }

    function createWallet(bytes32 x, bytes32 y) external returns (address) {
        
        // Encode x and y as immutable arguments
        bytes memory args = abi.encode(x, y);
        bytes32 salt = keccak256(args);
        
        // Use createDeterministicClone which doesn't revert if already deployed
        (bool alreadyDeployed, address instance) = LibClone.createDeterministicClone(IMPLEMENTATION, args, salt);
        if(!alreadyDeployed) {
            emit WalletCreated(instance, x, y);
        }
        return instance;
    }
}