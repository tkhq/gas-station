// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {TKGasDelegate} from "../TKGasDelegate.sol";
import {IArbiter} from "../interfaces/IArbiter.sol";

/// @title TKSmartWalletDelegate
/// @notice TKGasDelegate variant that delegates signature validation to a TKSmartWallet arbiter
/// @dev Inherits all logic from TKGasDelegate and only overrides signature validation
contract TKSmartWalletDelegate is TKGasDelegate {
    /// @notice Arbiter contract responsible for validating passkey signatures
    IArbiter public immutable ARBITER; 

    /// @notice Initializes the TKSmartWalletDelegate with a given arbiter contract
    /// @param _arbiterContract The contract that will perform signature validation
    constructor(address _arbiterContract) {
        ARBITER = IArbiter(_arbiterContract);
    }

    /// @inheritdoc TKGasDelegate
    function _validateSignature(bytes32 _hash, bytes calldata _signature)
        internal
        view
        override
        returns (bool)
    {
        return ARBITER.validateSignature(_hash, _signature);
    }
}


