// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ECDSA} from "solady/utils/ECDSA.sol";
import {EIP712} from "solady/utils/EIP712.sol";
import {IBatchExecution} from "./interfaces/IBatchExecution.sol";
import {ITKGasDelegate} from "./interfaces/ITKGasDelegate.sol";
import {IERC721Receiver} from "./interfaces/IERC721Receiver.sol";
import {IERC1155Receiver} from "./interfaces/IERC1155Receiver.sol";
import {IERC1721} from "./interfaces/IERC1721.sol";

/// @title TKGasDelegate
/// @notice Delegation contract for executing transactions with signature-based authorization
/// @dev Implements EIP-712 for typed structured data signing, supporting standard execution and batch execution
contract TKGasDelegate is EIP712, IERC1155Receiver, IERC721Receiver, IERC1721, ITKGasDelegate {
    error DeadlineExceeded();
    error InvalidNonce();
    error NotSelf();
    error ExecutionFailed();
    error InvalidOffset();

    bytes4 internal constant DEADLINE_EXCEEDED_SELECTOR = 0x559895a3;
    bytes4 internal constant ERC1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant INVALID_OFFSET_SELECTOR = 0x01da1572;

    bytes32 internal constant EXECUTION_TYPEHASH = 0x06bb52ccb5d61c4f9c5baafc0affaba32c4d02864c91221ad411291324aeea2e;
    // keccak256("Execution(uint128 nonce,uint32 deadline,address to,uint256 value,bytes data)")

    bytes32 internal constant BATCH_EXECUTION_TYPEHASH =
        0x14007e8c5dd696e52899952d0c28098ab95c056d082adc0d757f91c1306c7f55;
    // keccak256("BatchExecution(uint128 nonce,uint32 deadline,Call[] calls)Call(address to,uint256 value,bytes data)")

    bytes32 internal constant CALL_TYPEHASH = 0x9085b19ea56248c94d86174b3784cfaaa8673d1041d6441f61ff52752dac8483;
    // keccak256("Call(address to,uint256 value,bytes data)")

    bytes32 internal constant BURN_NONCE_TYPEHASH = 0x1abb8920e48045adda3ed0ce4be4357be95d4aa21af287280f532fc031584bda;
    // keccak256("BurnNonce(uint128 nonce)")

    /// @custom:storage-location erc7201:TKGasDelegate.state
    struct State {
        uint128 nonce;
    }

    bytes32 internal constant STATE_STORAGE_POSITION =
        0x34d5be385818fa5c8c4e7f9d5a028251d28ebab8aaf203a072d1dde2d49a1100;
    // Original: abi.encode(uint256(keccak256("TKGasDelegate.state")) - 1) & ~bytes32(uint256(0xff))

    function _getStateStorage() internal pure returns (State storage $) {
        assembly ("memory-safe") {
            $.slot := STATE_STORAGE_POSITION
        }
    }

    /// @notice Returns the current nonce for this delegate
    /// @dev The nonce increments with each transaction to prevent replay attacks
    /// @return The current nonce value
    function nonce() external view returns (uint128) {
        return _getStateStorage().nonce;
    }

    /// @notice Initializes the TKGasDelegate contract
    /// @dev Sets up EIP-712 domain separator with name "TKGasDelegate" and version "1"
    constructor() EIP712() {}

    // Internal helpers to centralize common validation logic

    function _validateExecute(bytes32 _hash, bytes calldata _signature, bytes calldata _nonceBytes) internal {
        _requireSelf(_hash, _signature);
        _consumeNonce(_nonceBytes);
    }

    function _requireSelf(bytes32 _hash, bytes calldata _signature) internal view {
        if (!_validateSignature(_hash, _signature)) {
            revert NotSelf();
        }
    }

    function _validateSignature(bytes32 _hash, bytes calldata _signature) internal view returns (bool) {
        return ECDSA.recoverCalldata(_hash, _signature) == address(this);
    }

    /// @notice Validates a signature against a hash
    /// @dev Recovers signer from signature and checks if it matches this contract's address
    /// @param _hash The hash that was signed
    /// @param _signature The signature to validate (65 bytes: r, s, v)
    /// @return true if the signature is valid, false otherwise
    function validateSignature(bytes32 _hash, bytes calldata _signature) external view returns (bool) {
        return _validateSignature(_hash, _signature);
    }

    /// @notice ERC-1271 compliant signature validation
    /// @dev Returns magic value 0x1626ba7e if signature is valid, 0xffffffff otherwise
    /// @param _hash The hash that was signed
    /// @param _signature The signature to validate
    /// @return Magic value indicating validity (0x1626ba7e for valid, 0xffffffff for invalid)
    function isValidSignature(bytes32 _hash, bytes calldata _signature) external view returns (bytes4) {
        if (_validateSignature(_hash, _signature)) {
            return ERC1271_MAGIC_VALUE;
        }
        return 0xffffffff;
    }

    function _consumeNonce(bytes calldata _nonceBytes) internal {
        uint128 nonceValue;
        State storage state = _getStateStorage();
        assembly ("memory-safe") {
            nonceValue := shr(128, calldataload(_nonceBytes.offset))
        }
        if (nonceValue != state.nonce) {
            revert InvalidNonce();
        }
        unchecked {
            ++state.nonce;
        }
    }

    function _consumeNonce(uint128 _nonce) internal {
        State storage state = _getStateStorage();
        if (_nonce != state.nonce) {
            revert InvalidNonce();
        }
        unchecked {
            ++state.nonce;
        }
    }

    /// @notice Returns the EIP-712 domain separator for this contract
    /// @dev Used for signature verification and typed data hashing
    /// @return The EIP-712 domain separator hash
    function getDomainSeparator() external view returns (bytes32) {
        return _domainSeparator();
    }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "TKGasDelegate";
        version = "1.1";
    }

    /// @notice Executes a transaction without returning data (gas-efficient)
    /// @dev Validates signature and nonce before execution
    /// @param _to The contract or address to call
    /// @param _value The amount of ETH to send (in wei)
    /// @param _data Encoded data containing signature (65 bytes), nonce (16 bytes), deadline (4 bytes), and arguments
    function execute(address _to, uint256 _value, bytes calldata _data) external {
        _value == 0
            ? _executeNoValueNoReturn(_data[0:65], _data[65:81], _data[81:85], _to, _data[85:])
            : _executeWithValueNoReturn(_data[0:65], _data[65:81], _data[81:85], _to, _value, _data[85:]);
    }

    /// @notice Executes a transaction with all parameters encoded in data, no return
    /// @dev Gas-efficient version when return data is not needed
    /// @param data Encoded data: signature(65) + nonce(16) + deadline(4) + to(20) + value(32) + arguments
    function execute(bytes calldata data) external {
        address to;
        uint256 value;
        assembly ("memory-safe") {
            // address is 20 bytes immediately after deadline
            to := shr(96, calldataload(add(data.offset, 85)))
            // value is 32 bytes immediately after address
            value := calldataload(add(data.offset, 105))
        }
        if (value == 0) {
            _executeNoValueNoReturn(data[0:65], data[65:81], data[81:85], to, data[137:]);
        } else {
            _executeWithValueNoReturn(data[0:65], data[65:81], data[81:85], to, value, data[137:]);
        }
    }

    /// @notice Executes a transaction with no ETH value and no return data
    /// @dev Most gas-efficient execution path for simple contract calls
    /// @param data Encoded data: signature(65) + nonce(16) + deadline(4) + to(20) + arguments
    function executeNoValueNoReturn(bytes calldata data) external {
        address to;
        assembly ("memory-safe") {
            // address is 20 bytes immediately after deadline
            to := shr(96, calldataload(add(data.offset, 85)))
        }
        _executeNoValueNoReturn(data[0:65], data[65:81], data[81:85], to, data[105:]);
    }

    /// @notice Burns a specific nonce to cancel a pending signed transaction
    /// @dev Requires a valid signature over the BurnNonce typehash. Allows end users to cancel transactions.
    /// @param _signature The 65-byte signature authorizing the nonce burn
    /// @param _nonce The nonce value to invalidate
    function burnNonce(bytes calldata _signature, uint128 _nonce) external {
        bytes32 hash;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, BURN_NONCE_TYPEHASH)
            mstore(add(ptr, 0x20), _nonce)
            hash := keccak256(ptr, 0x40)
            mstore(0x40, add(ptr, 0x40))
        }
        hash = _hashTypedData(hash);

        _requireSelf(hash, _signature);
        _consumeNonce(_nonce);
    }

    /// @notice Burns the current nonce without a signature; must be called by this contract itself
    /// @dev Increments the nonce to invalidate the current value
    function burnNonce() external {
        if (msg.sender != address(this) || msg.sender != tx.origin) {
            revert NotSelf();
        }
        unchecked {
            ++_getStateStorage().nonce;
        }
    }

    function _executeNoValueNoReturn(
        bytes calldata _signature,
        bytes calldata _nonceBytes,
        bytes calldata _deadlineBytes,
        address _outputContract,
        bytes calldata _arguments
    ) internal {
        bytes32 hash;
        assembly ("memory-safe") {
            let deadline := shr(224, calldataload(_deadlineBytes.offset))
            if gt(timestamp(), deadline) {
                let errorPtr := mload(0x40)
                mstore(errorPtr, DEADLINE_EXCEEDED_SELECTOR)
                revert(errorPtr, 0x04)
            } // DeadlineExceeded
            let ptr := mload(0x40)
            mstore(ptr, EXECUTION_TYPEHASH)
            let nonceValue := shr(128, calldataload(_nonceBytes.offset))
            mstore(add(ptr, 0x20), nonceValue)
            mstore(add(ptr, 0x40), deadline)
            mstore(add(ptr, 0x60), _outputContract)
            mstore(add(ptr, 0x80), 0)
            // Compute argsHash in assembly to avoid a separate solidity temp
            let argsPtr := add(ptr, 0xa0)
            calldatacopy(argsPtr, _arguments.offset, _arguments.length)
            let argsHash := keccak256(argsPtr, _arguments.length)
            mstore(add(ptr, 0xa0), argsHash)
            hash := keccak256(ptr, 0xc0)
            mstore(0x40, add(ptr, 0xc0))
        }
        hash = _hashTypedData(hash);

        _validateExecute(hash, _signature, _nonceBytes);

        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, _arguments.offset, _arguments.length)
            if iszero(call(gas(), _outputContract, 0, ptr, _arguments.length, 0, 0)) { revert(0, 0) }
            // No need to restore free memory pointer - execution ends immediately
        }
    }

    function _executeWithValueNoReturn(
        bytes calldata _signature,
        bytes calldata _nonceBytes,
        bytes calldata _deadlineBytes,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments
    ) internal {
        bytes32 argsHash = keccak256(_arguments);
        bytes32 hash; // all this assembly to avoid using abi.encode
        assembly ("memory-safe") {
            let deadline := shr(224, calldataload(_deadlineBytes.offset))
            if gt(timestamp(), deadline) {
                let errorPtr := mload(0x40)
                mstore(errorPtr, DEADLINE_EXCEEDED_SELECTOR)
                revert(errorPtr, 0x04)
            } // DeadlineExceeded
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, EXECUTION_TYPEHASH)
            let nonceValue := shr(128, calldataload(_nonceBytes.offset))
            mstore(add(ptr, 0x20), nonceValue)
            mstore(add(ptr, 0x40), deadline)
            mstore(add(ptr, 0x60), _outputContract)
            mstore(add(ptr, 0x80), _ethAmount)
            mstore(add(ptr, 0xa0), argsHash)
            hash := keccak256(ptr, 0xc0)
            mstore(0x40, add(ptr, 0xc0))
        }
        hash = _hashTypedData(hash);

        _validateExecute(hash, _signature, _nonceBytes);
        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, _arguments.offset, _arguments.length)
            if iszero(call(gas(), _outputContract, _ethAmount, ptr, _arguments.length, 0, 0)) { revert(0, 0) }
            // finish exection, no need to restore free memory pointer // mstore(0x40, add(ptr, _arguments.length))
        }
    }

    function _executeBatchWithCallsNoReturn(
        bytes calldata _signature,
        bytes calldata _nonceBytes,
        bytes calldata _deadlineBytes,
        IBatchExecution.Call[] calldata _calls
    ) internal {
        // Hash the calls array to match the calldata version exactly
        // The calldata version uses keccak256(_calls) where _calls is abi.encode(IBatchExecution.Call[])
        // So we need to hash the encoded calls array
        bytes32 executionsHash = _hashCallArrayUnchecked(_calls);
        bytes32 hash;
        assembly ("memory-safe") {
            let deadline := shr(224, calldataload(_deadlineBytes.offset))
            if gt(timestamp(), deadline) {
                let errorPtr := mload(0x40)
                mstore(errorPtr, DEADLINE_EXCEEDED_SELECTOR)
                revert(errorPtr, 0x04)
            } // DeadlineExceeded
            let ptr := mload(0x40)

            mstore(ptr, BATCH_EXECUTION_TYPEHASH)
            let nonceValue := shr(128, calldataload(_nonceBytes.offset))
            mstore(add(ptr, 0x20), nonceValue)
            mstore(add(ptr, 0x40), deadline)
            mstore(add(ptr, 0x60), executionsHash)
            hash := keccak256(ptr, 0x80)
            mstore(0x40, add(ptr, 0x80))
        }
        hash = _hashTypedData(hash);
        _validateExecute(hash, _signature, _nonceBytes);

        uint256 length = _calls.length;

        for (uint256 i; i < length;) {
            IBatchExecution.Call calldata execution = _calls[i];
            (bool success,) = execution.to.call{value: execution.value}(execution.data);
            if (!success) {
                revert ExecutionFailed();
            }
            unchecked {
                ++i;
            }
        }
    }

    function _executeBatchNoReturn(
        bytes calldata _signature,
        bytes calldata _nonceBytes,
        bytes calldata _deadlineBytes,
        bytes calldata _calls
    ) internal {
        IBatchExecution.Call[] calldata calls;
        uint256 length;
        assembly ("memory-safe") {
            // Read the offset pointer to determine where array data starts
            let offsetPointer := calldataload(_calls.offset)
            // If offset pointer is not 0x20, the length is not at the expected position
            if iszero(eq(offsetPointer, 0x20)) {
                let errorPtr := mload(0x40)
                mstore(errorPtr, INVALID_OFFSET_SELECTOR)
                revert(errorPtr, 0x04)
            }
            // With offset pointer = 0x20, length is at _calls.offset + 0x20, data starts at _calls.offset + 0x40
            let lengthPos := add(_calls.offset, 0x20)
            calls.offset := add(_calls.offset, 0x40)
            calls.length := calldataload(lengthPos)
            length := calls.length
        }

        bytes32 executionsHash = _hashCallArrayUnchecked(calls);
        bytes32 hash;
        assembly ("memory-safe") {
            let deadline := shr(224, calldataload(_deadlineBytes.offset))
            if gt(timestamp(), deadline) {
                let errorPtr := mload(0x40)
                mstore(errorPtr, DEADLINE_EXCEEDED_SELECTOR)
                revert(errorPtr, 0x04)
            } // DeadlineExceeded
            let ptr := mload(0x40)
            mstore(ptr, BATCH_EXECUTION_TYPEHASH)
            let nonceValue := shr(128, calldataload(_nonceBytes.offset))
            mstore(add(ptr, 0x20), nonceValue)
            mstore(add(ptr, 0x40), deadline)
            mstore(add(ptr, 0x60), executionsHash)
            hash := keccak256(ptr, 0x80)
            mstore(0x40, add(ptr, 0x80))
        }
        hash = _hashTypedData(hash);
        _validateExecute(hash, _signature, _nonceBytes);
        for (uint256 i = 0; i < length;) {
            IBatchExecution.Call calldata execution = calls[i];
            uint256 ethAmount = execution.value;
            address outputContract = execution.to;
            bytes calldata _callData2 = execution.data;
            assembly ("memory-safe") {
                let ptr := mload(0x40)
                calldatacopy(ptr, _callData2.offset, _callData2.length)
                if iszero(call(gas(), outputContract, ethAmount, ptr, _callData2.length, 0, 0)) { revert(0, 0) }
                mstore(0x40, add(ptr, _callData2.length))
            }
            unchecked {
                ++i;
            }
        }
    }

    function _hashCallArrayUnchecked(IBatchExecution.Call[] calldata _calls) internal pure returns (bytes32) {
        uint256 length = _calls.length;
        bytes32[] memory structHashes = new bytes32[](length);
        for (uint256 i; i < length;) {
            IBatchExecution.Call calldata c = _calls[i];
            structHashes[i] = keccak256(abi.encode(CALL_TYPEHASH, c.to, c.value, keccak256(c.data)));
            unchecked {
                ++i;
            }
        }
        return keccak256(abi.encodePacked(structHashes));
    }

    function executeBatch(IBatchExecution.Call[] calldata _calls, bytes calldata _data) external {
        _executeBatchWithCallsNoReturn(_data[0:65], _data[65:81], _data[81:85], _calls);
    }

    function executeBatch(bytes calldata data) external {
        _executeBatchNoReturn(data[0:65], data[65:81], data[81:85], data[85:]);
    }

    /**
     * @dev Needed to allow the smart wallet to receive ETH and ERC1155/721 tokens
     */
    receive() external payable {
        // Allow receiving ETH
    }

    // ERC721 Receiver function
    function onERC721Received(
        address, /* operator */
        address, /* from */
        uint256, /* tokenId */
        bytes calldata /* data */
    ) external pure override returns (bytes4) {
        return 0x150b7a02;
    }

    // ERC1155 Receiver function
    function onERC1155Received(
        address, /* operator */
        address, /* from */
        uint256, /* id */
        uint256, /* value */
        bytes calldata /* data */
    ) external pure override returns (bytes4) {
        return 0xf23a6e61;
    }

    // ERC1155 Batch Receiver function
    function onERC1155BatchReceived(
        address, /* operator */
        address, /* from */
        uint256[] calldata, /* ids */
        uint256[] calldata, /* values */
        bytes calldata /* data */
    ) external pure override returns (bytes4) {
        return 0xbc197c81;
    }

    /// @notice ERC-165 interface detection
    /// @dev Returns true if this contract supports the given interface
    /// @param _interfaceId The interface identifier to check
    /// @return true if the interface is supported
    function supportsInterface(bytes4 _interfaceId) external pure returns (bool) {
        return _interfaceId == 0x01ffc9a7 // ERC165 Interface ID
            || _interfaceId == 0x150b7a02 // ERC721Receiver Interface ID
            || _interfaceId == 0x4e2312e0; // ERC1155Receiver Interface ID (xor of onERC1155Received and onERC1155BatchReceived)
    }

    // View functions

    /// @notice Computes the hash of a batch execution call array
    /// @dev Used internally for batch execution signature verification
    /// @param _calls Array of Call structs to hash
    /// @return The keccak256 hash of the encoded call array
    function hashCallArray(IBatchExecution.Call[] calldata _calls) external pure returns (bytes32) {
        return _hashCallArrayUnchecked(_calls);
    }

    /// @notice Computes the EIP-712 typed data hash for a nonce burn
    /// @param _nonce The nonce to be burned
    /// @return The EIP-712 compliant hash to be signed
    function hashBurnNonce(uint128 _nonce) external view returns (bytes32) {
        bytes32 hash;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, BURN_NONCE_TYPEHASH)
            mstore(add(ptr, 0x20), _nonce)
            hash := keccak256(ptr, 0x40)
            mstore(0x40, add(ptr, 0x40))
        }
        return _hashTypedData(hash);
    }

    /// @notice Computes the EIP-712 typed data hash for an execution
    /// @dev Used by clients to generate the hash that must be signed for execute functions
    /// @param _nonce The nonce for replay protection
    /// @param _deadline The Unix timestamp after which the signature expires
    /// @param _to The contract or address to call
    /// @param _value The amount of ETH to send (in wei)
    /// @param _data The calldata for the transaction
    /// @return The EIP-712 compliant hash to be signed
    function hashExecution(uint128 _nonce, uint32 _deadline, address _to, uint256 _value, bytes calldata _data)
        external
        view
        returns (bytes32)
    {
        bytes32 argsHash = keccak256(_data);
        bytes32 hash;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _nonce)
            mstore(add(ptr, 0x40), _deadline)
            mstore(add(ptr, 0x60), _to)
            mstore(add(ptr, 0x80), _value)
            mstore(add(ptr, 0xa0), argsHash)
            hash := keccak256(ptr, 0xc0)
            mstore(0x40, add(ptr, 0xc0))
        }
        return _hashTypedData(hash);
    }

    /// @notice Computes the EIP-712 typed data hash for a batch execution
    /// @dev Used to generate the hash for executing multiple transactions atomically
    /// @param _nonce The nonce for replay protection
    /// @param _deadline The Unix timestamp after which the signature expires
    /// @param _calls Array of Call structs containing the batch operations
    /// @return The EIP-712 compliant hash to be signed
    function hashBatchExecution(uint128 _nonce, uint32 _deadline, IBatchExecution.Call[] calldata _calls)
        external
        view
        returns (bytes32)
    {
        bytes32 executionsHash = _hashCallArrayUnchecked(_calls); // no validation done here, you can make hashes that are invalid with too long or 0 length arrays
        bytes32 hash;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, BATCH_EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _nonce)
            mstore(add(ptr, 0x40), _deadline)
            mstore(add(ptr, 0x60), executionsHash)
            hash := keccak256(ptr, 0x80)
            mstore(0x40, add(ptr, 0x80))
        }
        return _hashTypedData(hash);
    }
}
