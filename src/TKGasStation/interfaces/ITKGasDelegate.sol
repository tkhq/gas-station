// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IBatchExecution} from "./IBatchExecution.sol";

/// @title ITKGasDelegate
/// @notice Interface for the delegation contract that executes transactions with signature-based authorization
/// @dev Supports multiple execution modes: standard execution, batch execution, sessions, and ERC20 approve-then-execute patterns
interface ITKGasDelegate is IBatchExecution {
    /// @notice Returns the current nonce for this delegate
    /// @return The current nonce value
    function nonce() external view returns (uint128);
    function getNonce(uint64 _prefix) external view returns (uint128);

    /// @notice Validates a signature against a hash
    /// @param _hash The hash that was signed
    /// @param _signature The signature to validate (65 bytes)
    /// @return true if the signature is valid
    function validateSignature(bytes32 _hash, bytes calldata _signature) external view returns (bool);

    /// @notice Checks if a session counter has been burned/expired
    /// @param _counter The session counter to check
    /// @return true if the counter has been burned
    function checkSessionCounterExpired(uint128 _counter) external view returns (bool);

    /// @notice ERC-165 interface detection
    /// @param _interfaceId The interface identifier to check
    /// @return true if the interface is supported
    function supportsInterface(bytes4 _interfaceId) external pure returns (bool);

    // Execute functions
    /// @notice Executes a transaction with all parameters encoded in data, returns result
    /// @param _data Encoded data: signature(65) + nonce(16) + deadline(4) + to(20) + value(32) + arguments
    /// @return The return data from the executed call
    function executeReturns(bytes calldata _data) external returns (bytes memory);

    /// @notice Executes a transaction with all parameters encoded in data, no return
    /// @param _data Encoded data: signature(65) + nonce(16) + deadline(4) + to(20) + value(32) + arguments
    function execute(bytes calldata _data) external;

    /// @notice Executes a transaction with no ETH value and no return data
    /// @param _data Encoded data: signature(65) + nonce(16) + deadline(4) + to(20) + arguments
    function executeNoValueNoReturn(bytes calldata _data) external;

    /// @notice Executes a transaction and returns the result
    /// @param _to The contract or address to call
    /// @param _value The amount of ETH to send (in wei)
    /// @param _data Encoded data containing signature, nonce, deadline, and arguments
    /// @return The return data from the executed call
    function executeReturns(address _to, uint256 _value, bytes calldata _data) external returns (bytes memory);

    /// @notice Executes a transaction without returning data
    /// @param _to The contract or address to call
    /// @param _value The amount of ETH to send (in wei)
    /// @param _data Encoded data containing signature, nonce, deadline, and arguments
    function execute(address _to, uint256 _value, bytes calldata _data) external;

    //ApproveThenExecute functions

    /// @notice Approves ERC20 tokens then executes a transaction, returning the result
    /// @param _data Encoded data: signature(65) + nonce(16) + deadline(4) + erc20(20) + spender(20) + approveAmount(32) + to(20) + value(32) + arguments
    /// @return The return data from the executed call
    function approveThenExecuteReturns(bytes calldata _data) external returns (bytes memory);

    /// @notice Approves ERC20 tokens then executes a transaction, no return
    /// @param _data Encoded data: signature(65) + nonce(16) + deadline(4) + erc20(20) + spender(20) + approveAmount(32) + to(20) + value(32) + arguments
    function approveThenExecute(bytes calldata _data) external;

    /// @notice Approves ERC20 tokens then executes a transaction, returns result
    /// @param _to The contract to call after approval
    /// @param _value The amount of ETH to send (in wei)
    /// @param _erc20 The ERC20 token contract to approve
    /// @param _spender The address that will be approved to spend tokens
    /// @param _approveAmount The amount of tokens to approve
    /// @param _data Encoded signature, nonce, deadline, and call arguments
    /// @return The return data from the executed call
    function approveThenExecuteReturns(
        address _to,
        uint256 _value,
        address _erc20,
        address _spender,
        uint256 _approveAmount,
        bytes calldata _data
    ) external returns (bytes memory);

    /// @notice Approves ERC20 tokens then executes a transaction, no return
    /// @param _to The contract to call after approval
    /// @param _value The amount of ETH to send (in wei)
    /// @param _erc20 The ERC20 token contract to approve
    /// @param _spender The address that will be approved to spend tokens
    /// @param _approveAmount The amount of tokens to approve
    /// @param _data Encoded signature, nonce, deadline, and call arguments
    function approveThenExecute(
        address _to,
        uint256 _value,
        address _erc20,
        address _spender,
        uint256 _approveAmount,
        bytes calldata _data
    ) external;

    // Batch execute functions

    /// @notice Executes multiple transactions in a single call, returns all results
    /// @param _data Encoded data: signature(65) + nonce(16) + deadline(4) + abi.encode(Call[])
    /// @return Array of return data from each executed call
    function executeBatchReturns(bytes calldata _data) external returns (bytes[] memory);

    /// @notice Executes multiple transactions in a single call, no return
    /// @param _data Encoded data: signature(65) + nonce(16) + deadline(4) + abi.encode(Call[])
    function executeBatch(bytes calldata _data) external;

    /// @notice Executes multiple transactions with explicit call array, returns results
    /// @param _calls Array of Call structs containing the batch operations
    /// @param _data Encoded signature, nonce, and deadline
    /// @return Array of return data from each executed call
    function executeBatchReturns(IBatchExecution.Call[] calldata _calls, bytes calldata _data)
        external
        returns (bytes[] memory);

    /// @notice Executes multiple transactions with explicit call array, no return
    /// @param _calls Array of Call structs containing the batch operations
    /// @param _data Encoded signature, nonce, and deadline
    function executeBatch(IBatchExecution.Call[] calldata _calls, bytes calldata _data) external;

    // Batch session execute functions
    function executeBatchSessionReturns(bytes calldata _data) external returns (bytes[] memory);

    function executeBatchSession(bytes calldata _data) external;

    function executeBatchSessionReturns(IBatchExecution.Call[] calldata _calls, bytes calldata _data)
        external
        returns (bytes[] memory);

    function executeBatchSession(IBatchExecution.Call[] calldata _calls, bytes calldata _data) external;

    // Session execute functions
    function executeSessionReturns(bytes calldata _data) external returns (bytes memory);

    function executeSession(bytes calldata _data) external;

    function executeSessionReturns(address _to, uint256 _value, bytes calldata _data) external returns (bytes memory);

    function executeSession(address _to, uint256 _value, bytes calldata _data) external;

    // Arbitrary session functions
    function executeSessionArbitraryReturns(bytes calldata _data) external returns (bytes memory);

    function executeSessionArbitrary(bytes calldata _data) external;

    function executeSessionArbitraryReturns(address _to, uint256 _value, bytes calldata _data)
        external
        returns (bytes memory);

    function executeSessionArbitrary(address _to, uint256 _value, bytes calldata _data) external;

    // Arbitrary batch session functions

    function executeBatchSessionArbitraryReturns(bytes calldata _data) external returns (bytes[] memory);

    function executeBatchSessionArbitrary(bytes calldata _data) external;

    function executeBatchSessionArbitraryReturns(IBatchExecution.Call[] calldata _calls, bytes calldata _data)
        external
        returns (bytes[] memory);

    function executeBatchSessionArbitrary(IBatchExecution.Call[] calldata _calls, bytes calldata _data) external;

    // Burn functions
    /// @notice Burns a specific nonce to invalidate it
    /// @param _signature The signature authorizing the nonce burn
    /// @param _nonce The nonce value to burn
    function burnNonce(bytes calldata _signature, uint128 _nonce) external;

    /// @notice Burns a session counter to revoke all sessions using that counter
    /// @param _signature The signature authorizing the counter burn
    /// @param _counter The session counter value to burn
    function burnSessionCounter(bytes calldata _signature, uint128 _counter) external;

    /// @notice Burns the current nonce without signature (must be called by self)
    function burnNonce() external;
    
    /// @notice Burns the current nonce without signature (must be called by self)
    /// @param _prefix The prefix of the next nonce to burn
    function burnNonce(uint64 _prefix) external;

    /// @notice Burns a session counter without signature (must be called by self)
    /// @param _counter The session counter value to burn
    function burnSessionCounter(uint128 _counter) external;

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

    /// @notice Computes the EIP-712 typed data hash for burning a nonce
    /// @param _nonce The nonce value to burn
    /// @return The EIP-712 compliant hash to be signed
    function hashBurnNonce(uint128 _nonce) external view returns (bytes32);

    /// @notice Computes the EIP-712 typed data hash for approve-then-execute
    /// @param _nonce The nonce for replay protection
    /// @param _deadline The Unix timestamp after which the signature expires
    /// @param _erc20Contract The ERC20 token to approve
    /// @param _spender The address to approve
    /// @param _approveAmount The amount of tokens to approve
    /// @param _to The contract to call after approval
    /// @param _value The amount of ETH to send (in wei)
    /// @param _data The calldata for the transaction
    /// @return The EIP-712 compliant hash to be signed
    function hashApproveThenExecute(
        uint128 _nonce,
        uint32 _deadline,
        address _erc20Contract,
        address _spender,
        uint256 _approveAmount,
        address _to,
        uint256 _value,
        bytes calldata _data
    ) external view returns (bytes32);

    /// @notice Computes the EIP-712 typed data hash for a session execution
    /// @param _counter The session counter for replay protection
    /// @param _deadline The Unix timestamp after which the signature expires
    /// @param _sender The address authorized to execute in this session
    /// @param _to The contract that can be called in this session
    /// @return The EIP-712 compliant hash to be signed
    function hashSessionExecution(uint128 _counter, uint32 _deadline, address _sender, address _to)
        external
        view
        returns (bytes32);

    /// @notice Computes the EIP-712 typed data hash for an arbitrary session execution
    /// @param _counter The session counter for replay protection
    /// @param _deadline The Unix timestamp after which the signature expires
    /// @param _sender The address authorized to execute arbitrary transactions
    /// @return The EIP-712 compliant hash to be signed
    function hashArbitrarySessionExecution(uint128 _counter, uint32 _deadline, address _sender)
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

    /// @notice Computes the EIP-712 typed data hash for burning a session counter
    /// @param _counter The session counter value to burn
    /// @return The EIP-712 compliant hash to be signed
    function hashBurnSessionCounter(uint128 _counter) external view returns (bytes32);
}
