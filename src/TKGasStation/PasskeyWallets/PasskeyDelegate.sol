// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {TKGasDelegate} from "../TKGasDelegate.sol";
import {IArbiter} from "../interfaces/IArbiter.sol";

/// @title PasskeyDelegate
/// @notice TKGasDelegate variant that delegates signature validation to a Passkey arbiter
/// @dev Inherits all logic from TKGasDelegate and only overrides signature validation
contract PasskeyDelegate is TKGasDelegate {
    /// @notice Arbiter contract responsible for validating passkey signatures
    address public immutable ARBITER_CONTRACT;

    /// @notice Initializes the PasskeyDelegate with a given arbiter contract
    /// @param _arbiterContract The contract that will perform signature validation
    constructor(address _arbiterContract) {
        ARBITER_CONTRACT = _arbiterContract;
    }

    /// @inheritdoc TKGasDelegate
    function _validateSignature(bytes32 _hash, bytes calldata _signature)
        internal
        view
        override
        returns (bool)
    {
        return IArbiter(ARBITER_CONTRACT).validateSignature(_hash, _signature);
    }
}


