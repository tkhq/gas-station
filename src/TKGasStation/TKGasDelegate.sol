// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ECDSA} from "solady/utils/ECDSA.sol";
import {EIP712} from "solady/utils/EIP712.sol";
import {IBatchExecution} from "./interfaces/IBatchExecution.sol";
import {ITKGasDelegate} from "./interfaces/ITKGasDelegate.sol";
import {IERC721Receiver} from "./interfaces/IERC721Receiver.sol";
import {IERC1155Receiver} from "./interfaces/IERC1155Receiver.sol";

contract TKGasDelegate is EIP712, IERC1155Receiver, IERC721Receiver, ITKGasDelegate {
    error BatchSizeExceeded();
    error DeadlineExceeded();
    error InvalidOutputContract();
    error InvalidNonce();
    error InvalidCounter();
    error NotSelf();
    error ExecutionFailed();
    error UnknownFunctionSelector();
    error NoEthAllowed();

    bytes32 private constant EXECUTION_TYPEHASH = 0xcd5f5d65a387f188fe5c0c9265c7e7ec501fa0b0ee45ad769c119694cac5d895;
    // Original: keccak256("Execution(uint128 nonce,address outputContract,uint256 ethAmount,bytes arguments)")

    bytes32 private constant BATCH_EXECUTION_TYPEHASH =
        0x55e88ae5d875bf1c64043249314f1ead2a2fcd11e1e423107ef7e93aafc30182;
    // Original: keccak256("BatchExecution(uint128 nonce,Call[] calls)Call(address to,uint256 value,bytes data)")

    bytes32 private constant BURN_NONCE_TYPEHASH = 0x1abb8920e48045adda3ed0ce4be4357be95d4aa21af287280f532fc031584bda;
    // Original: keccak256("BurnNonce(uint128 nonce)")

    bytes32 private constant SESSION_EXECUTION_TYPEHASH =
        0x201d4aaf5ff3955fc1d5d6b55f97c35e43833bc3500f8bd2d83a9e43b36a67d9;
    // Original: keccak256("SessionExecution(uint128 counter,uint128 deadline,address sender,address outputContract)")

    bytes32 private constant ARBITRARY_SESSION_EXECUTION_TYPEHASH =
        0x8529aa3645658aca043e9bb16844886a22b47f90b0f2ca58ad6a5c0e4e427fd7;
    // Original: keccak256("ArbitrarySessionExecution(uint128 counter,uint128 deadline,address sender)")

    bytes32 private constant BURN_SESSION_COUNTER_TYPEHASH =
        0x9e83fc2d99981f8f5e9cca6e9253e48163b75f85c9f1e80235a9380203430d4f;
    // Original: keccak256("BurnSessionCounter(uint128 counter,address sender)")

    // Maximum batch size to prevent griefing attacks
    uint256 public constant MAX_BATCH_SIZE = 50;
    uint8 public constant ETH_AMOUNT_MAX_LENGTH_BYTES = 10; // max 1.2m eth if using the fallback function

    uint128 public sessionCounter;
    uint128 public nonce;

    constructor() EIP712() {}

    fallback(bytes calldata) external returns (bytes memory) {
        // session based auth is not used with this fallback function
        bytes1 secondByte = bytes1(msg.data[1]);
        // Extract function selector from first nibble (bits 7-4)
        bytes1 functionSelector = secondByte & 0xF0;

        // Extract nonce length from last nibble (bits 3-0) - counts up from 0, so 0 means 1 byte
        uint8 nonceEnd = 68 + uint8(secondByte & 0x0F);

        // Extract signature (65 bytes: bytes 2-66)
        bytes calldata signature = msg.data[2:67];
        // Extract nonce value (variable length)
        bytes calldata nonceBytes = msg.data[67:nonceEnd];
        uint128 nonceValue;
        assembly {
            // Load the nonce bytes and shift to get the correct value
            let nonceData := calldataload(add(nonceBytes.offset, 0x20))
            // Shift right to align the nonce value (32 bytes - nonce length)
            let shiftAmount := sub(256, mul(8, nonceBytes.length))
            nonceValue := shr(shiftAmount, nonceData)
        }

        if (functionSelector == bytes1(0x00)) {
            // Extract output contract address (20 bytes)
            address outputContract;
            assembly {
                outputContract := shr(96, calldataload(nonceEnd))
            }

            bytes calldata arguments = msg.data[nonceEnd + 20:];
            (, bytes memory result) = _execute(signature, nonceValue, outputContract, arguments);
            return result;
        }
        if (functionSelector == bytes1(0x10)) {
            // Extract output contract address (20 bytes)
            address outputContract;
            assembly {
                outputContract := shr(96, calldataload(nonceEnd))
            }

            // Extract ETH amount (variable length)
            uint256 ethAmount;
            assembly {
                let loaded := calldataload(add(nonceEnd, 20))
                // Shift right to get only the 10 bytes we want (shift by 22 bytes = 176 bits)
                ethAmount := shr(176, loaded)
            }

            bytes calldata arguments = msg.data[nonceEnd + 20 + ETH_AMOUNT_MAX_LENGTH_BYTES:];
            (, bytes memory result) = _executeWithValue(signature, nonceValue, outputContract, ethAmount, arguments);
            return result;
        }

        revert UnknownFunctionSelector();
    }

    // Internal helpers to centralize common validation logic
    function _requireSelf(bytes32 _hash, bytes calldata _signature, address _expected) internal view {
        if (ECDSA.recover(_hash, _signature) != _expected) {
            revert NotSelf();
        }
    }

    function _consumeNonce(uint128 _nonce) internal {
        if (_nonce != nonce) {
            revert InvalidNonce();
        }
        unchecked {
            ++nonce;
        }
    }

    function _requireCounter(uint128 _counter) internal view {
        if (_counter != sessionCounter) {
            revert InvalidCounter();
        }
    }

    function _performCall(address _outputContract, bytes calldata _arguments) internal returns (bool, bytes memory) {
        (bool success, bytes memory result) = _outputContract.call(_arguments);
        if (success) {
            return (success, result);
        }
        revert ExecutionFailed();
    }

    function _performCallWithValue(address _outputContract, uint256 _ethAmount, bytes calldata _arguments)
        internal
        returns (bool, bytes memory)
    {
        (bool success, bytes memory result) = _outputContract.call{value: _ethAmount}(_arguments);
        if (success) {
            return (success, result);
        }
        revert ExecutionFailed();
    }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "TKGasDelegate";
        version = "1";
    }

    function hashExecution(uint128 _nonce, address _outputContract, uint256 _ethAmount, bytes calldata _arguments)
        external
        view
        returns (bytes32)
    {
        bytes32 argsHash = keccak256(_arguments);
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _nonce)
            mstore(add(ptr, 0x40), _outputContract)
            mstore(add(ptr, 0x60), _ethAmount)
            mstore(add(ptr, 0x80), argsHash)
            hash := keccak256(ptr, 0xa0)
        }
        return _hashTypedData(hash);
    }

    function execute(bytes calldata data) external returns (bool, bytes memory) {
        uint128 thisNonce;
        address to;
        uint256 value;
        assembly {
            // nonce is 16 bytes at offset 65
            thisNonce := shr(128, calldataload(add(data.offset, 65)))
            // address is 20 bytes immediately after nonce
            to := shr(96, calldataload(add(data.offset, 81)))
            // value is 32 bytes immediately after address
            value := calldataload(add(data.offset, 101))
        }
        if (value == 0) {
            return _execute(data[0:65], thisNonce, to, data[133:]);
        }
        return _executeWithValue(data[0:65], thisNonce, to, value, data[133:]);
    }

    function executeNoValue(bytes calldata data) external returns (bool, bytes memory) {
        uint128 thisNonce;
        address to;
        assembly {
            // nonce is 16 bytes at offset 65
            thisNonce := shr(128, calldataload(add(data.offset, 65)))
            // address is 20 bytes immediately after nonce
            to := shr(96, calldataload(add(data.offset, 81)))
        }
        return _execute(data[0:65], thisNonce, to, data[101:]);
    }

    function _execute(bytes calldata _signature, uint128 _nonce, address _outputContract, bytes calldata _arguments)
        internal
        returns (bool, bytes memory)
    {
        bytes32 argsHash = keccak256(_arguments);
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _nonce)
            mstore(add(ptr, 0x40), _outputContract)
            mstore(add(ptr, 0x60), 0) // ethAmount = 0
            mstore(add(ptr, 0x80), argsHash)
            hash := keccak256(ptr, 0xa0)
        }
        hash = _hashTypedData(hash);

        _requireSelf(hash, _signature, address(this));
        _consumeNonce(_nonce);
        return _performCall(_outputContract, _arguments);
    }

    function _executeWithValue(
        bytes calldata _signature,
        uint128 _nonce,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments
    ) internal returns (bool, bytes memory) {
        bytes32 argsHash = keccak256(_arguments);
        bytes32 hash; // all this assembly to avoid using abi.encode
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _nonce)
            mstore(add(ptr, 0x40), _outputContract)
            mstore(add(ptr, 0x60), _ethAmount)
            mstore(add(ptr, 0x80), argsHash)
            hash := keccak256(ptr, 0xa0)
        }
        hash = _hashTypedData(hash);

        _requireSelf(hash, _signature, address(this));
        _consumeNonce(_nonce);
        return _performCallWithValue(_outputContract, _ethAmount, _arguments);
    }

    function hashBurnNonce(uint128 _nonce) external view returns (bytes32) {
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, BURN_NONCE_TYPEHASH)
            mstore(add(ptr, 0x20), _nonce)
            hash := keccak256(ptr, 0x40)
        }
        return _hashTypedData(hash);
    }

    function burnNonce(bytes calldata _signature, uint128 _nonce) external {
        bytes32 hash;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, BURN_NONCE_TYPEHASH)
            mstore(add(ptr, 0x20), _nonce)
            hash := keccak256(ptr, 0x40)
        }
        hash = _hashTypedData(hash);

        _requireSelf(hash, _signature, address(this));
        _consumeNonce(_nonce);
    }

    function burnNonce() external {
        if (msg.sender != address(this) || msg.sender != tx.origin) {
            revert NotSelf();
        }
        unchecked {
            ++nonce;
        }
    }

    /* Session execution */

    function hashSessionExecution(uint128 _counter, uint128 _deadline, address _sender, address _outputContract)
        external
        view
        returns (bytes32)
    {
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, SESSION_EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _counter)
            mstore(add(ptr, 0x40), _deadline)
            mstore(add(ptr, 0x60), _sender)
            mstore(add(ptr, 0x80), _outputContract)
            hash := keccak256(ptr, 0xa0)
        }
        return _hashTypedData(hash);
    }

    function hashArbitrarySessionExecution(uint128 _counter, uint128 _deadline, address _sender)
        external
        view
        returns (bytes32)
    {
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, ARBITRARY_SESSION_EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _counter)
            mstore(add(ptr, 0x40), _deadline)
            mstore(add(ptr, 0x60), _sender)
            hash := keccak256(ptr, 0x80)
        }
        return _hashTypedData(hash);
    }

    function hashBurnSessionCounter(uint128 _counter, address _sender) external view returns (bytes32) {
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, BURN_SESSION_COUNTER_TYPEHASH)
            mstore(add(ptr, 0x20), _counter)
            mstore(add(ptr, 0x40), _sender)
            hash := keccak256(ptr, 0x60)
        }
        return _hashTypedData(hash);
    }

    function _executeSessionWithValue(
        bytes calldata _signature,
        uint128 _counter,
        uint128 _deadline,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments
    ) internal returns (bool, bytes memory) {
        // Check if deadline has passed
        if (block.timestamp > _deadline) {
            revert DeadlineExceeded();
        }

        address sender = msg.sender;
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, SESSION_EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _counter)
            mstore(add(ptr, 0x40), _deadline)
            mstore(add(ptr, 0x60), sender)
            mstore(add(ptr, 0x80), _outputContract)
            hash := keccak256(ptr, 0xa0)
        }
        hash = _hashTypedData(hash);

        _requireCounter(_counter);
        _requireSelf(hash, _signature, address(this));

        (bool success, bytes memory result) = _outputContract.call{value: _ethAmount}(_arguments);

        if (success) {
            return (success, result);
        }
        revert ExecutionFailed();
    }

    function _executeSession(
        bytes calldata _signature,
        uint128 _counter,
        uint128 _deadline,
        address _outputContract,
        bytes calldata _arguments
    ) internal returns (bool, bytes memory) {
        // Check if deadline has passed
        if (block.timestamp > _deadline) {
            revert DeadlineExceeded();
        }

        address sender = msg.sender;
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, SESSION_EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _counter)
            mstore(add(ptr, 0x40), _deadline)
            mstore(add(ptr, 0x60), sender)
            mstore(add(ptr, 0x80), _outputContract)
            hash := keccak256(ptr, 0xa0)
        }
        hash = _hashTypedData(hash);

        _requireCounter(_counter);
        _requireSelf(hash, _signature, address(this));
        // Execute the session transaction (counter does NOT increment for session)
        return _performCall(_outputContract, _arguments);
    }

    function _executeBatchSession(
        bytes calldata _signature,
        uint128 _counter,
        uint128 _deadline,
        address _outputContract,
        IBatchExecution.Call[] calldata _calls
    ) internal returns (bool, bytes[] memory) {
        // Check if deadline has passed
        if (block.timestamp > _deadline) {
            revert DeadlineExceeded();
        }
        if (_calls.length > MAX_BATCH_SIZE) {
            revert BatchSizeExceeded();
        }

        address sender = msg.sender;
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, SESSION_EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _counter)
            mstore(add(ptr, 0x40), _deadline)
            mstore(add(ptr, 0x60), sender)
            mstore(add(ptr, 0x80), _outputContract)
            hash := keccak256(ptr, 0xa0)
        }
        hash = _hashTypedData(hash);
        _requireCounter(_counter);
        _requireSelf(hash, _signature, address(this));
        for (uint256 i = 0; i < _calls.length;) {
            if (_calls[i].to != _outputContract) {
                revert InvalidOutputContract();
            }
            unchecked {
                ++i;
            }
        }

        // Execute the session transaction
        uint256 length = _calls.length;
        bytes[] memory results = new bytes[](length);

        // Cache array access to avoid repeated calldata reads
        for (uint256 i = 0; i < length;) {
            IBatchExecution.Call calldata execution = _calls[i];
            uint256 ethAmount = execution.value;
            address outputContract = execution.to;

            (bool success, bytes memory result) = ethAmount == 0
                ? _performCall(outputContract, execution.data)
                : _performCallWithValue(outputContract, ethAmount, execution.data);

            results[i] = result;

            if (!success) revert ExecutionFailed();

            unchecked {
                ++i;
            }
        }

        return (true, results);
    }

    function _executeSessionArbitrary(
        bytes calldata _signature,
        uint128 _counter,
        uint128 _deadline,
        address _outputContract,
        bytes calldata _arguments
    ) internal returns (bool, bytes memory) {
        // Check if deadline has passed
        if (block.timestamp > _deadline) {
            revert DeadlineExceeded();
        }

        address sender = msg.sender;
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, ARBITRARY_SESSION_EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _counter)
            mstore(add(ptr, 0x40), _deadline)
            mstore(add(ptr, 0x60), sender)
            hash := keccak256(ptr, 0x80)
        }
        hash = _hashTypedData(hash);
        _requireCounter(_counter);
        _requireSelf(hash, _signature, address(this));
        // Execute the session transaction
        return _performCall(_outputContract, _arguments);
    }

    function _executeSessionArbitraryWithValue(
        bytes calldata _signature,
        uint128 _counter,
        uint128 _deadline,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments
    ) internal returns (bool, bytes memory) {
        // Check if deadline has passed
        if (block.timestamp > _deadline) {
            revert DeadlineExceeded();
        }

        address sender = msg.sender;
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, ARBITRARY_SESSION_EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _counter)
            mstore(add(ptr, 0x40), _deadline)
            mstore(add(ptr, 0x60), sender)
            hash := keccak256(ptr, 0x80)
        }
        hash = _hashTypedData(hash);
        _requireCounter(_counter);
        _requireSelf(hash, _signature, address(this));
        // Execute the session transaction
        return _performCallWithValue(_outputContract, _ethAmount, _arguments);
    }

    function _executeBatchSessionArbitrary(
        bytes calldata _signature,
        uint128 _counter,
        uint128 _deadline,
        IBatchExecution.Call[] calldata _calls
    ) internal returns (bool, bytes[] memory) {
        // Check if deadline has passed
        if (block.timestamp > _deadline) {
            revert DeadlineExceeded();
        }
        // Prevent griefing attacks by limiting batch size
        if (_calls.length > MAX_BATCH_SIZE) {
            revert BatchSizeExceeded();
        }

        address sender = msg.sender;
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, ARBITRARY_SESSION_EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _counter)
            mstore(add(ptr, 0x40), _deadline)
            mstore(add(ptr, 0x60), sender)
            hash := keccak256(ptr, 0x80)
        }
        hash = _hashTypedData(hash);
        _requireCounter(_counter);
        _requireSelf(hash, _signature, address(this));
        // Execute the session transaction
        uint256 length = _calls.length;
        bytes[] memory results = new bytes[](length);

        // Cache array access to avoid repeated calldata reads
        for (uint256 i = 0; i < length;) {
            IBatchExecution.Call calldata execution = _calls[i];
            uint256 ethAmount = execution.value;
            address outputContract = execution.to;

            (bool success, bytes memory result) = ethAmount == 0
                ? _performCall(outputContract, execution.data)
                : _performCallWithValue(outputContract, ethAmount, execution.data);

            results[i] = result;

            if (!success) revert ExecutionFailed();

            unchecked {
                ++i;
            }
        }

        return (true, results);
    }

    function burnSessionCounter(bytes calldata _signature, uint128 _counter, address _sender) external {
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, BURN_SESSION_COUNTER_TYPEHASH)
            mstore(add(ptr, 0x20), _counter)
            mstore(add(ptr, 0x40), _sender)
            hash := keccak256(ptr, 0x60)
        }
        hash = _hashTypedData(hash);

        _requireCounter(_counter);
        if (ECDSA.recover(hash, _signature) != address(this)) {
            revert NotSelf();
        }
        unchecked {
            ++sessionCounter;
        }
    }

    function burnSessionCounter() external {
        if (msg.sender != address(this) || msg.sender != tx.origin) {
            revert NotSelf();
        }
        unchecked {
            ++sessionCounter;
        }
    }

    function hashBatchExecution(uint128 _nonce, IBatchExecution.Call[] calldata _calls)
        external
        view
        returns (bytes32)
    {
        bytes32 executionsHash = keccak256(abi.encode(_calls));
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, BATCH_EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _nonce)
            mstore(add(ptr, 0x40), executionsHash)
            hash := keccak256(ptr, 0x60)
        }
        return _hashTypedData(hash);
    }

    /* Bytes-encoded entrypoints to match refactored interface */
    function executeSession(bytes calldata data) external returns (bool, bytes memory) {
        // Layout: [signature(65)][counter(16)][deadline(16)][sender(20)][output(20)][args]
        bytes calldata signature = data[0:65];
        uint128 counter;
        uint128 deadline;
        address output;
        assembly {
            counter := shr(128, calldataload(add(data.offset, 65)))
            deadline := shr(128, calldataload(add(data.offset, 81)))
            output := shr(96, calldataload(add(data.offset, 97)))
        }
        bytes calldata args = data[117:];
        return _executeSession(signature, counter, deadline, output, args);
    }

    function executeBatchSession(bytes calldata data) external returns (bool, bytes[] memory) {
        // Layout: [signature(65)][counter(16)][deadline(16)][output(20)][abi.encode(IBatchExecution.Call[])]
        bytes calldata signature = data[0:65];
        uint128 counter;
        uint128 deadline;
        address output;
        assembly {
            counter := shr(128, calldataload(add(data.offset, 65)))
            deadline := shr(128, calldataload(add(data.offset, 81)))
            output := shr(96, calldataload(add(data.offset, 97)))
        }
        IBatchExecution.Call[] calldata calls;
        assembly {
            calls.offset := add(data.offset, 117)
            calls.length := calldataload(add(data.offset, 117))
        }
        return _executeBatchSession(signature, counter, deadline, output, calls);
    }

    function executeSessionArbitrary(bytes calldata data) external returns (bool, bytes memory) {
        // Layout: [signature(65)][counter(16)][deadline(16)][sender(20)][output(20)][args]
        bytes calldata signature = data[0:65];
        uint128 counter;
        uint128 deadline;
        address output;
        assembly {
            counter := shr(128, calldataload(add(data.offset, 65)))
            deadline := shr(128, calldataload(add(data.offset, 81)))
            output := shr(96, calldataload(add(data.offset, 97)))
        }
        bytes calldata args = data[117:];
        return _executeSessionArbitrary(signature, counter, deadline, output, args);
    }

    function executeBatchSessionArbitrary(bytes calldata data) external returns (bool, bytes[] memory) {
        // Layout: [signature(65)][counter(16)][deadline(16)][abi.encode(IBatchExecution.Call[])]
        bytes calldata signature = data[0:65];
        uint128 counter;
        uint128 deadline;
        assembly {
            counter := shr(128, calldataload(add(data.offset, 65)))
            deadline := shr(128, calldataload(add(data.offset, 81)))
        }
        IBatchExecution.Call[] calldata calls;
        assembly {
            calls.offset := add(data.offset, 97)
            calls.length := calldataload(add(data.offset, 97))
        }
        return _executeBatchSessionArbitrary(signature, counter, deadline, calls);
    }

    function executeBatch(bytes calldata data) external returns (bool, bytes[] memory) {
        // Layout: [signature(65)][nonce(16)][abi.encode(IBatchExecution.Call[])]
        bytes calldata signature = data[0:65];
        uint128 thisNonce;
        assembly {
            thisNonce := shr(128, calldataload(add(data.offset, 65)))
        }

        // Hash the raw encoded calls slice to match the off-chain preimage exactly
        bytes32 executionsHash = keccak256(data[81:]);
        bytes32 hash;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, BATCH_EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), thisNonce)
            mstore(add(ptr, 0x40), executionsHash)
            hash := keccak256(ptr, 0x60)
        }
        hash = _hashTypedData(hash);
        _requireSelf(hash, signature, address(this));
        _consumeNonce(thisNonce);

        IBatchExecution.Call[] memory calls = abi.decode(data[81:], (IBatchExecution.Call[]));

        uint256 length = calls.length;
        // Prevent griefing attacks by limiting batch size
        if (length > MAX_BATCH_SIZE) {
            revert BatchSizeExceeded();
        }
        bytes[] memory results = new bytes[](length);

        for (uint256 i = 0; i < length;) {
            IBatchExecution.Call memory execution = calls[i];
            uint256 ethAmount = execution.value;
            address outputContract = execution.to;
            (bool success, bytes memory result) = ethAmount == 0
                ? outputContract.call(execution.data)
                : outputContract.call{value: ethAmount}(execution.data);

            results[i] = result;
            if (!success) revert ExecutionFailed();
            unchecked {
                ++i;
            }
        }
        return (true, results);
    }

    function _executeBatch(bytes calldata _signature, uint128 _nonce, IBatchExecution.Call[] calldata _calls)
        internal
        returns (bool, bytes[] memory)
    {
        // Prevent griefing attacks by limiting batch size
        if (_calls.length > MAX_BATCH_SIZE) {
            revert BatchSizeExceeded();
        }

        bytes32 executionsHash = keccak256(abi.encode(_calls));
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, BATCH_EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _nonce)
            mstore(add(ptr, 0x40), executionsHash)
            hash := keccak256(ptr, 0x60)
        }
        hash = _hashTypedData(hash);
        _consumeNonce(_nonce);
        _requireSelf(hash, _signature, address(this));

        uint256 length = _calls.length;
        bytes[] memory results = new bytes[](length);

        // Cache array access to avoid repeated calldata reads
        for (uint256 i = 0; i < length;) {
            IBatchExecution.Call calldata execution = _calls[i];
            uint256 ethAmount = execution.value;
            address outputContract = execution.to;
            // Do not cache arguments to save on copy costs
            (bool success, bytes memory result) = ethAmount == 0
                ? outputContract.call(execution.data)
                : outputContract.call{value: ethAmount}(execution.data);

            results[i] = result;

            if (!success) revert ExecutionFailed();

            unchecked {
                ++i;
            }
        }

        return (true, results);
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
}
