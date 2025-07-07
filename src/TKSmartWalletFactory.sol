// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {TKSmartWalletManager} from "./TKSmartWalletManager.sol";
import {BasicTKSmartWallet} from "./BasicTKSmartWallet.sol";

contract TKSmartWalletFactory {

    event SmartWalletCreated(string name, string version, address owner, address interactionContract, bytes4[] allowedFunctions, address manager, address smartWallet);

    function createSmartWallet(string memory _name, string memory _version, address _owner, address _interactionContract, bytes4[] memory _allowedFunctions) external returns (address, address payable) {
        address manager = address(new TKSmartWalletManager(_name, _version, _owner, _interactionContract, _allowedFunctions));
        address payable smartWallet = payable(address(new BasicTKSmartWallet(manager)));

        emit SmartWalletCreated(_name, _version, _owner, _interactionContract, _allowedFunctions, manager, smartWallet);

        return (manager, smartWallet);
    }
}