// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ITKGasDelegate} from "./interfaces/ITKGasDelegate.sol";
import {ITKGasStation} from "./interfaces/ITKGasStation.sol";
import {IBatchExecution} from "./interfaces/IBatchExecution.sol";

/// @title TKGasStation
/// @notice Gas station contract that routes execution calls to delegated EOA accounts
/// @dev This contract acts as an intermediary that validates delegated EOAs and forwards execution calls to TKGasDelegate
contract TKGasStation is ITKGasStation {
    error NotDelegated();
    error InvalidFunctionSelector();
    error ExecutionFailed();

    address public immutable TK_GAS_DELEGATE;

    /// @notice Initializes the gas station with the TKGasDelegate implementation address
    /// @param _tkGasDelegate Address of the TKGasDelegate contract that delegated EOAs point to
    constructor(address _tkGasDelegate) {
        TK_GAS_DELEGATE = _tkGasDelegate;
    }

    fallback(bytes calldata data) external returns (bytes memory) {
        address target;
        assembly {
            target := shr(96, calldataload(add(data.offset, 1)))
        }
        if (!_isDelegated(target)) {
            revert NotDelegated();
        }

        if (bytes1(data[21]) == 0x00) {
            // check if the first byte is 0x00
            bytes1 functionSelector = bytes1(data[22] & 0xf0); // mask the last nibble

            // only allow execute functions, no session functions
            if (functionSelector == 0x00 || functionSelector == 0x10 || functionSelector == 0x20) {
                (bool success, bytes memory result) = target.call(data[21:]);
                if (success) {
                    return result;
                }
                revert ExecutionFailed();
            }
        }

        revert InvalidFunctionSelector();
    }

    function _isDelegated(address _targetEoA) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(_targetEoA)
        }
        if (size != 23) {
            return false;
        }

        bytes memory code = new bytes(23);
        assembly {
            extcodecopy(_targetEoA, add(code, 0x20), 0, 23)
        }
        // prefix is 0xef0100
        if (code[0] != 0xef || code[1] != 0x01 || code[2] != 0x00) {
            return false;
        }

        address delegatedTo;

        assembly {
            // Load the 20-byte address from bytes 3-22
            delegatedTo := shr(96, mload(add(code, 0x23)))
        }

        return delegatedTo == TK_GAS_DELEGATE;
    }

    // Execute functions
    /// @notice Executes a transaction on behalf of a delegated EOA and returns the result
    /// @dev Validates that _target is properly delegated before forwarding the call
    /// @param _target The delegated EOA address that will execute the transaction
    /// @param _to The contract or address to call
    /// @param _ethAmount The amount of ETH to send with the call (in wei)
    /// @param _data The encoded function call data including signature, nonce, deadline, and arguments
    /// @return The return data from the executed call
    function executeReturns(address _target, address _to, uint256 _ethAmount, bytes calldata _data)
        external
        returns (bytes memory)
    {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        bytes memory result = ITKGasDelegate(_target).executeReturns(_to, _ethAmount, _data);
        return result;
    }

    /// @notice Executes a transaction on behalf of a delegated EOA without returning data
    /// @dev Validates that _target is properly delegated before forwarding the call. Gas-efficient version for calls that don't need return data
    /// @param _target The delegated EOA address that will execute the transaction
    /// @param _to The contract or address to call
    /// @param _ethAmount The amount of ETH to send with the call (in wei)
    /// @param _data The encoded function call data including signature, nonce, deadline, and arguments
    function execute(address _target, address _to, uint256 _ethAmount, bytes calldata _data) external {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        ITKGasDelegate(_target).execute(_to, _ethAmount, _data);
    }

    // ApproveThenExecute functions
    /// @notice Approves an ERC20 spender then executes a transaction, returning the result
    /// @dev Validates delegation, approves ERC20 tokens, then executes the call. Useful for DEX interactions and similar patterns
    /// @param _target The delegated EOA address that will execute the transaction
    /// @param _to The contract or address to call after approval
    /// @param _ethAmount The amount of ETH to send with the call (in wei)
    /// @param _erc20 The ERC20 token contract to approve
    /// @param _spender The address that will be approved to spend tokens
    /// @param _approveAmount The amount of tokens to approve
    /// @param _data The encoded function call data including signature, nonce, deadline, and arguments
    /// @return The return data from the executed call
    function approveThenExecuteReturns(
        address _target,
        address _to,
        uint256 _ethAmount,
        address _erc20,
        address _spender,
        uint256 _approveAmount,
        bytes calldata _data
    ) external returns (bytes memory) {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        bytes memory result =
            ITKGasDelegate(_target).approveThenExecuteReturns(_to, _ethAmount, _erc20, _spender, _approveAmount, _data);
        return result;
    }

    /// @notice Approves an ERC20 spender then executes a transaction without returning data
    /// @dev Validates delegation, approves ERC20 tokens, then executes the call. Gas-efficient version for calls that don't need return data
    /// @param _target The delegated EOA address that will execute the transaction
    /// @param _to The contract or address to call after approval
    /// @param _ethAmount The amount of ETH to send with the call (in wei)
    /// @param _erc20 The ERC20 token contract to approve
    /// @param _spender The address that will be approved to spend tokens
    /// @param _approveAmount The amount of tokens to approve
    /// @param _data The encoded function call data including signature, nonce, deadline, and arguments
    function approveThenExecute(
        address _target,
        address _to,
        uint256 _ethAmount,
        address _erc20,
        address _spender,
        uint256 _approveAmount,
        bytes calldata _data
    ) external {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        ITKGasDelegate(_target).approveThenExecute(_to, _ethAmount, _erc20, _spender, _approveAmount, _data);
    }

    // Batch execute functions
    /// @notice Executes multiple transactions in a single call and returns all results
    /// @dev Validates delegation before forwarding batch execution. All calls must succeed or the entire batch reverts
    /// @param _target The delegated EOA address that will execute the transactions
    /// @param _calls Array of Call structs containing to, value, and data for each transaction
    /// @param _data The encoded signature, nonce, and deadline for batch authorization
    /// @return Array of return data from each executed call, in the same order as _calls
    function executeBatchReturns(address _target, IBatchExecution.Call[] calldata _calls, bytes calldata _data)
        external
        returns (bytes[] memory)
    {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        bytes[] memory results = ITKGasDelegate(_target).executeBatchReturns(_calls, _data);
        return results;
    }

    /// @notice Executes multiple transactions in a single call without returning data
    /// @dev Validates delegation before forwarding batch execution. Gas-efficient version when return data is not needed
    /// @param _target The delegated EOA address that will execute the transactions
    /// @param _calls Array of Call structs containing to, value, and data for each transaction
    /// @param _data The encoded signature, nonce, and deadline for batch authorization
    function executeBatch(address _target, IBatchExecution.Call[] calldata _calls, bytes calldata _data) external {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        ITKGasDelegate(_target).executeBatch(_calls, _data);
    }

    /// @notice Invalidates a specific nonce to prevent replay attacks or cancel pending operations
    /// @dev Validates delegation before allowing nonce burn. Requires signature authorization from the EOA owner
    /// @param _targetEoA The delegated EOA address whose nonce will be burned
    /// @param _signature The signature authorizing the nonce burn operation
    /// @param _nonce The nonce value to invalidate
    function burnNonce(address _targetEoA, bytes calldata _signature, uint128 _nonce) external {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        ITKGasDelegate(_targetEoA).burnNonce(_signature, _nonce);
    }

    /* Lense Functions */

    /// @notice Retrieves the current nonce for a delegated EOA
    /// @dev The nonce increments with each executed transaction to prevent replay attacks
    /// @param _targetEoA The delegated EOA address to query
    /// @return The current nonce value (uint128)
    function getNonce(address _targetEoA) external view returns (uint128) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        uint128 nonce = ITKGasDelegate(_targetEoA).nonce();
        return nonce;
    }

    /// @notice Checks if an address is properly delegated to the TK_GAS_DELEGATE
    /// @dev Verifies the EOA has the correct delegation bytecode (0xef0100 prefix + TK_GAS_DELEGATE address)
    /// @param _targetEoA The address to check for delegation status
    /// @return true if the address is delegated to TK_GAS_DELEGATE, false otherwise
    function isDelegated(address _targetEoA) external view returns (bool) {
        return _isDelegated(_targetEoA);
    }

    /// @notice Validates a signature against a hash for a delegated EOA
    /// @dev Uses ECDSA recovery to verify the signature was created by the EOA owner
    /// @param _targetEoA The delegated EOA address that should have signed the hash
    /// @param _hash The hash that was signed (typically an EIP-712 typed data hash)
    /// @param _signature The signature bytes to validate (65 bytes: r, s, v)
    /// @return true if the signature is valid for the given hash and EOA, false otherwise
    function validateSignature(address _targetEoA, bytes32 _hash, bytes calldata _signature)
        external
        view
        returns (bool)
    {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(_targetEoA).validateSignature(_hash, _signature);
    }

    // Hash function lenses
    /// @notice Computes the EIP-712 typed data hash for an execution operation
    /// @dev Used by clients to generate the hash that must be signed for execute functions
    /// @param _targetEoA The delegated EOA that will execute the transaction
    /// @param _nonce The nonce to use for replay protection
    /// @param _deadline The Unix timestamp after which the signature expires
    /// @param _outputContract The contract or address to call
    /// @param _ethAmount The amount of ETH to send (in wei)
    /// @param _arguments The calldata to send to the output contract
    /// @return The EIP-712 compliant hash to be signed
    function hashExecution(
        address _targetEoA,
        uint128 _nonce,
        uint32 _deadline,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments
    ) external view returns (bytes32) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(_targetEoA).hashExecution(_nonce, _deadline, _outputContract, _ethAmount, _arguments);
    }

    /// @notice Computes the EIP-712 typed data hash for burning a nonce
    /// @dev Used to generate the hash that must be signed to invalidate a nonce
    /// @param _targetEoA The delegated EOA whose nonce will be burned
    /// @param _nonce The nonce value to burn
    /// @return The EIP-712 compliant hash to be signed
    function hashBurnNonce(address _targetEoA, uint128 _nonce) external view returns (bytes32) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(_targetEoA).hashBurnNonce(_nonce);
    }

    /// @notice Computes the EIP-712 typed data hash for an approve-then-execute operation
    /// @dev Used to generate the hash that must be signed for ERC20 approval followed by execution
    /// @param _targetEoA The delegated EOA that will execute the transaction
    /// @param _nonce The nonce to use for replay protection
    /// @param _deadline The Unix timestamp after which the signature expires
    /// @param _erc20Contract The ERC20 token contract to approve
    /// @param _spender The address that will be approved to spend tokens
    /// @param _approveAmount The amount of tokens to approve
    /// @param _outputContract The contract to call after approval
    /// @param _ethAmount The amount of ETH to send with the call (in wei)
    /// @param _arguments The calldata to send to the output contract
    /// @return The EIP-712 compliant hash to be signed
    function hashApproveThenExecute(
        address _targetEoA,
        uint128 _nonce,
        uint32 _deadline,
        address _erc20Contract,
        address _spender,
        uint256 _approveAmount,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments
    ) external view returns (bytes32) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(_targetEoA).hashApproveThenExecute(
            _nonce, _deadline, _erc20Contract, _spender, _approveAmount, _outputContract, _ethAmount, _arguments
        );
    }

    /// @notice Computes the EIP-712 typed data hash for a session execution operation
    /// @dev Sessions allow a sender to execute transactions on behalf of the EOA to a specific contract
    /// @param _targetEoA The delegated EOA for this session
    /// @param _counter The session counter for replay protection (different from nonce)
    /// @param _deadline The Unix timestamp after which the signature expires
    /// @param _sender The address authorized to execute transactions in this session
    /// @param _outputContract The specific contract that can be called in this session
    /// @return The EIP-712 compliant hash to be signed
    function hashSessionExecution(
        address _targetEoA,
        uint128 _counter,
        uint32 _deadline,
        address _sender,
        address _outputContract
    ) external view returns (bytes32) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(_targetEoA).hashSessionExecution(_counter, _deadline, _sender, _outputContract);
    }

    /// @notice Computes the EIP-712 typed data hash for an arbitrary session execution
    /// @dev Arbitrary sessions allow a sender to execute transactions to any contract (not restricted)
    /// @param _targetEoA The delegated EOA for this session
    /// @param _counter The session counter for replay protection
    /// @param _deadline The Unix timestamp after which the signature expires
    /// @param _sender The address authorized to execute arbitrary transactions
    /// @return The EIP-712 compliant hash to be signed
    function hashArbitrarySessionExecution(address _targetEoA, uint128 _counter, uint32 _deadline, address _sender)
        external
        view
        returns (bytes32)
    {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(_targetEoA).hashArbitrarySessionExecution(_counter, _deadline, _sender);
    }

    /// @notice Computes the EIP-712 typed data hash for a batch execution operation
    /// @dev Used to generate the hash for executing multiple calls atomically
    /// @param _targetEoA The delegated EOA that will execute the batch
    /// @param _nonce The nonce to use for replay protection
    /// @param _deadline The Unix timestamp after which the signature expires
    /// @param _calls Array of Call structs containing the batch operations
    /// @return The EIP-712 compliant hash to be signed
    function hashBatchExecution(
        address _targetEoA,
        uint128 _nonce,
        uint32 _deadline,
        IBatchExecution.Call[] calldata _calls
    ) external view returns (bytes32) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(_targetEoA).hashBatchExecution(_nonce, _deadline, _calls);
    }

    /// @notice Computes the EIP-712 typed data hash for burning a session counter
    /// @dev Used to invalidate all future uses of a session with the given counter
    /// @param _targetEoA The delegated EOA whose session counter will be burned
    /// @param _counter The session counter value to burn
    /// @return The EIP-712 compliant hash to be signed
    function hashBurnSessionCounter(address _targetEoA, uint128 _counter) external view returns (bytes32) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(_targetEoA).hashBurnSessionCounter(_counter);
    }
}
