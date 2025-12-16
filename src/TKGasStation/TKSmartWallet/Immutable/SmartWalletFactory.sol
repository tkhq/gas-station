// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {LibClone} from "solady/utils/LibClone.sol";

import {IInitializableDelegate} from "../interfaces/IInitializableDelegate.sol";


contract SmartWalletFactory {
    address public immutable IMPLEMENTATION;

    constructor(address _implementation) {
        IMPLEMENTATION = _implementation;
    }

    function createWallet(bytes memory _data) external returns (address instance, bytes memory returnData) {
        instance = LibClone.cloneDeterministic(IMPLEMENTATION, _data);
        returnData = _initialize(instance, _data);
    }

    function _initialize(address _instance, bytes memory _data) internal virtual returns (bytes memory) {
        IInitializableDelegate(_instance).initialize(_data);
        return _data;
    }
}