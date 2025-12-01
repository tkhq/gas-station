// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @title IBatchExecution
/// @notice Interface defining the structure for batch transaction execution
/// @dev Provides the Call struct used to represent individual transactions in a batch
interface IBatchExecution {
    /// @notice Represents a single transaction call in a batch execution
    /// @dev Contains all necessary parameters to execute a transaction
    /// @param to The target address to call (contract or EOA)
    /// @param value The amount of ETH to send with the call (in wei)
    /// @param data The calldata to send to the target address
    struct Call {
        address to;
        uint256 value;
        bytes data;
    }
}
