// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IBatchExecution} from "./IBatchExecution.sol";

/// @title ITKGasDelegate
/// @notice Interface for the delegation contract that executes transactions with signature-based authorization
/// @dev Supports standard execution and batch execution modes
interface ITKGasDelegate is IBatchExecution {
    /// @notice Returns the current nonce for this delegate
    /// @return The current nonce value
    function nonce() external view returns (uint128);

    /// @notice Validates a signature against a hash
    /// @param _hash The hash that was signed
    /// @param _signature The signature to validate (65 bytes)
    /// @return true if the signature is valid
    function validateSignature(bytes32 _hash, bytes calldata _signature) external view returns (bool);

    /// @notice ERC-165 interface detection
    /// @param _interfaceId The interface identifier to check
    /// @return true if the interface is supported
    function supportsInterface(bytes4 _interfaceId) external pure returns (bool);

    // Execute functions
    /// @notice Executes a transaction with all parameters encoded in data, no return
    /// @param _data Encoded data: signature(65) + nonce(16) + deadline(4) + to(20) + value(32) + arguments
    function execute(bytes calldata _data) external;

    /// @notice Executes a transaction with no ETH value and no return data
    /// @param _data Encoded data: signature(65) + nonce(16) + deadline(4) + to(20) + arguments
    function executeNoValueNoReturn(bytes calldata _data) external;

    /// @notice Executes a transaction without returning data
    /// @param _to The contract or address to call
    /// @param _value The amount of ETH to send (in wei)
    /// @param _data Encoded data containing signature, nonce, deadline, and arguments
    function execute(address _to, uint256 _value, bytes calldata _data) external;

    // Batch execute functions

    /// @notice Executes multiple transactions in a single call, no return
    /// @param _data Encoded data: signature(65) + nonce(16) + deadline(4) + abi.encode(Call[])
    function executeBatch(bytes calldata _data) external;

    /// @notice Executes multiple transactions with explicit call array, no return
    /// @param _calls Array of Call structs containing the batch operations
    /// @param _data Encoded signature, nonce, and deadline
    function executeBatch(IBatchExecution.Call[] calldata _calls, bytes calldata _data) external;

    // Hash functions
    /// @notice Computes the EIP-712 typed data hash for an execution
    /// @param _nonce The nonce for replay protection
    /// @param _deadline The Unix timestamp after which the signature expires
    /// @param _to The contract or address to call
    /// @param _value The amount of ETH to send (in wei)
    /// @param _data The calldata for the transaction
    /// @return The EIP-712 compliant hash to be signed
    function hashExecution(uint128 _nonce, uint32 _deadline, address _to, uint256 _value, bytes calldata _data)
        external
        view
        returns (bytes32);

    /// @notice Computes the EIP-712 typed data hash for a batch execution
    /// @param _nonce The nonce for replay protection
    /// @param _deadline The Unix timestamp after which the signature expires
    /// @param _calls Array of Call structs containing the batch operations
    /// @return The EIP-712 compliant hash to be signed
    function hashBatchExecution(uint128 _nonce, uint32 _deadline, IBatchExecution.Call[] calldata _calls)
        external
        view
        returns (bytes32);
}
