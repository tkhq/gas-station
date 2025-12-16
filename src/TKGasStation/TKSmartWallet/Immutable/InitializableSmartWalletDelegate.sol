// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {TKGasDelegate} from "../TKGasDelegate.sol";
import {IInitializableDelegate} from "../interfaces/IInitializableDelegate.sol";


abstract contract InitializableSmartWalletDelegate is TKGasDelegate, IInitializableDelegate {
    /// @notice This is a smart wallet that is initialized with a particular factory
    address public immutable INITIALIZER; 
    bool public initialized;

    constructor(address _initializer) {
        INITIALIZER = _initializer;
    }

    function initialize(bytes memory _data) external returns (bytes memory) {
        if (msg.sender != INITIALIZER) {
            revert NotAuthorized();
        }
        if (initialized) {
            revert AlreadyInitialized();
        }
        initialized = true;
        return _initialize(_data);
    }

    function _initialize(bytes memory _data) internal virtual returns (bytes memory);
}


