// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IBatchExecution} from "./IBatchExecution.sol";

/// @title ITKGasStation
/// @notice Interface for the gas station contract that routes execution calls to delegated EOAs
/// @dev Provides functions for executing transactions and managing nonces through delegated accounts
interface ITKGasStation is IBatchExecution {
    /// @notice Returns the address of the TKGasDelegate implementation
    /// @return The address of the TKGasDelegate contract
    function TK_GAS_DELEGATE() external view returns (address);

    // Execute functions
    /// @notice Executes a transaction on behalf of a delegated EOA and returns the result
    /// @param _target The delegated EOA address that will execute the transaction
    /// @param _to The contract or address to call
    /// @param _ethAmount The amount of ETH to send with the call (in wei)
    /// @param _data The encoded function call data including signature, nonce, deadline, and arguments
    /// @return The return data from the executed call
    function executeReturns(address _target, address _to, uint256 _ethAmount, bytes calldata _data)
        external
        returns (bytes memory);

    /// @notice Executes a transaction on behalf of a delegated EOA without returning data
    /// @param _target The delegated EOA address that will execute the transaction
    /// @param _to The contract or address to call
    /// @param _ethAmount The amount of ETH to send with the call (in wei)
    /// @param _data The encoded function call data including signature, nonce, deadline, and arguments
    function execute(address _target, address _to, uint256 _ethAmount, bytes calldata _data) external;

    // Batch execute functions
    /// @notice Executes multiple transactions in a single call and returns all results
    /// @param _target The delegated EOA address that will execute the transactions
    /// @param _calls Array of Call structs containing to, value, and data for each transaction
    /// @param _data The encoded signature, nonce, and deadline for batch authorization
    /// @return Array of return data from each executed call
    function executeBatchReturns(address _target, IBatchExecution.Call[] calldata _calls, bytes calldata _data)
        external
        returns (bytes[] memory);

    /// @notice Executes multiple transactions in a single call without returning data
    /// @param _target The delegated EOA address that will execute the transactions
    /// @param _calls Array of Call structs containing to, value, and data for each transaction
    /// @param _data The encoded signature, nonce, and deadline for batch authorization
    function executeBatch(address _target, IBatchExecution.Call[] calldata _calls, bytes calldata _data) external;

    /// @notice Retrieves the current nonce for a delegated EOA
    /// @param _targetEoA The delegated EOA address to query
    /// @return The current nonce value
    function getNonce(address _targetEoA) external view returns (uint128);

    /// @notice Checks if an address is properly delegated to the TK_GAS_DELEGATE
    /// @param _targetEoA The address to check for delegation status
    /// @return true if the address is delegated, false otherwise
    function isDelegated(address _targetEoA) external view returns (bool);
}
