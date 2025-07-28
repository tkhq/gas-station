// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {BasicTKSmartWallet} from "./BasicTKSmartWallet.sol";

contract Factory {
    event SmartWalletCreated(address indexed interactionContract, bytes4[] allowedFunctions, address indexed smartWallet);

    function createSmartWallet(address _interactionContract, bytes4[] memory _allowedFunctions) external returns (address payable) {
        address payable smartWallet = payable(address(new BasicTKSmartWallet(_interactionContract, false, _allowedFunctions)));
        emit SmartWalletCreated(_interactionContract, _allowedFunctions, smartWallet);
        return smartWallet;
    }
/*
    function createSmartWalletWithManager(address _interactionContract, bytes4[] memory _allowedFunctions) external returns (address payable) {
        address payable smartWallet = payable(address(new BasicTKSmartWallet(_interactionContract, true, _allowedFunctions)));
        emit SmartWalletCreated(_interactionContract, _allowedFunctions, smartWallet);
        return smartWallet;
    }
    */
}