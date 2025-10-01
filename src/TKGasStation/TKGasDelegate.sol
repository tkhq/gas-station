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
    error NoEthAllowed();
    error UnsupportedExecutionMode();

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
    uint8 public constant MAX_BATCH_SIZE = 50;
    // Fallback function optimizations
    uint8 public constant ETH_AMOUNT_MAX_LENGTH_BYTES = 10; // max 1.2m eth if using the fallback function
    uint8 public constant DEADLINE_MAX_LENGTH_BYTES = 5; // up to ~34 years in seconds
    uint8 public constant CONTRACT_LENGTH_BYTES = 20; // just for convenience 

    State public state;

    constructor() EIP712() {}

    fallback(bytes calldata) external returns (bytes memory) {
        bool returnBytes = msg.data[0] == 0x01;
        bytes1 secondByte = bytes1(msg.data[1]);
        bytes1 functionSelector = secondByte & 0xF0;
        uint256 nonceEnd = 68 + uint8(secondByte & 0x0F);
        
        bytes calldata signature = msg.data[2:67];
        bytes calldata nonceBytes = msg.data[67:nonceEnd];
        uint128 nonceValue;
        assembly {
            let nonceData := calldataload(add(nonceBytes.offset, 0x20))
            let shiftAmount := sub(256, mul(8, nonceBytes.length))
            nonceValue := shr(shiftAmount, nonceData)
        }

        // Optimize for most common cases first (0x00 and 0x10)
        if (functionSelector == bytes1(0x00)) { // execute (no value)
            address outputContract;
            bytes calldata arguments;
            assembly {
                outputContract := shr(96, calldataload(nonceEnd))
                arguments.offset := add(nonceEnd, 20)
                arguments.length := sub(calldatasize(), add(nonceEnd, 20))
            }
            if (returnBytes) {
                (, bytes memory result) = _execute(signature, nonceValue, outputContract, arguments);
                return result;
            }
            _execute(signature, nonceValue, outputContract, arguments);
            assembly { return(0x00, 0x00) }
        } else if (functionSelector == bytes1(0x10)) { // executeWithValue
            address outputContract;
            uint256 ethAmount;
            bytes calldata arguments;
            assembly {
                outputContract := shr(96, calldataload(nonceEnd))
                let loaded := calldataload(add(nonceEnd, 20))
                ethAmount := shr(176, loaded)
                arguments.offset := add(nonceEnd, 30)
                arguments.length := sub(calldatasize(), add(nonceEnd, 30))
            }
            if (returnBytes) {
                (, bytes memory result) = _executeWithValue(signature, nonceValue, outputContract, ethAmount, arguments);
                return result;
            }
            _executeWithValue(signature, nonceValue, outputContract, ethAmount, arguments);
            assembly { return(0x00, 0x00) }
        } else if (functionSelector == bytes1(0x20)) { // executeBatch
            if (returnBytes) {
                (, bytes[] memory result) = _executeBatch(signature, nonceValue, msg.data[nonceEnd:]);
                return abi.encode(result);
            }
            _executeBatch(signature, nonceValue, msg.data[nonceEnd:]);
            assembly {
                return(0x00, 0x00)
            }
        } else if (functionSelector == bytes1(0x30)) { // executeSession
            uint128 deadline;
            address outputContract;
            bytes calldata arguments;
            assembly {
                let loaded := calldataload(nonceEnd)
                deadline := shr(216, loaded)
                outputContract := shr(96, calldataload(add(nonceEnd, 5)))
                arguments.offset := add(nonceEnd, 25)
                arguments.length := sub(calldatasize(), add(nonceEnd, 25))
            }
            if (returnBytes) {
                (, bytes memory result) = _executeSession(signature, nonceValue, deadline, outputContract, arguments);
                return result;
            }
            _executeSession(signature, nonceValue, deadline, outputContract, arguments);
            assembly { return(0x00, 0x00) }
        } else if (functionSelector == bytes1(0x40)) { // executeSessionWithValue
            uint128 deadline;
            address outputContract;
            uint256 ethAmount;
            bytes calldata arguments;
            assembly {
                let loaded := calldataload(nonceEnd)
                deadline := shr(216, loaded)
                outputContract := shr(96, calldataload(add(nonceEnd, 5)))
                loaded := calldataload(add(nonceEnd, 20))
                ethAmount := shr(176, loaded)
                arguments.offset := add(nonceEnd, 35)
                arguments.length := sub(calldatasize(), add(nonceEnd, 35))
            }
            if (returnBytes) {
                (, bytes memory result) = _executeSessionWithValue(signature, nonceValue, deadline, outputContract, ethAmount, arguments);
                return result;
            }
            _executeSessionWithValue(signature, nonceValue, deadline, outputContract, ethAmount, arguments);
            assembly { return(0x00, 0x00) }
        } else if (functionSelector == bytes1(0x50)) { // executeBatchSession
            uint128 deadline;
            address outputContract;
            IBatchExecution.Call[] calldata calls;
            assembly {
                let loaded := calldataload(nonceEnd)
                deadline := shr(216, loaded)
                outputContract := shr(96, calldataload(add(nonceEnd, 5)))
                let head := add(nonceEnd, 25)
                calls.length := calldataload(head)
                calls.offset := add(head, 0x20)
            }
            if (returnBytes) {
                (, bytes[] memory result) = _executeBatchSession(signature, nonceValue, deadline, outputContract, calls);
                return abi.encode(result);
            }
            _executeBatchSession(signature, nonceValue, deadline, outputContract, calls);
            assembly { return(0x00, 0x00) }
        } else if (functionSelector == bytes1(0x60)) { // executeSessionArbitrary
            uint128 deadline;
            address outputContract;
            bytes calldata arguments;
            assembly {
                let loaded := calldataload(nonceEnd)
                deadline := shr(216, loaded)
                outputContract := shr(96, calldataload(add(nonceEnd, 5)))
                arguments.offset := add(nonceEnd, 25)
                arguments.length := sub(calldatasize(), add(nonceEnd, 25))
            }
            if (returnBytes) {
                (, bytes memory result) = _executeSessionArbitrary(signature, nonceValue, deadline, outputContract, arguments);
                return result;
            }
            _executeSessionArbitrary(signature, nonceValue, deadline, outputContract, arguments);
            assembly { return(0x00, 0x00) }
        } else if (functionSelector == bytes1(0x70)) { // executeSessionArbitraryWithValue
            uint128 deadline;
            address outputContract;
            uint256 ethAmount;
            bytes calldata arguments;
            assembly {
                let loaded := calldataload(nonceEnd)
                deadline := shr(216, loaded)
                outputContract := shr(96, calldataload(add(nonceEnd, 5)))
                loaded := calldataload(add(nonceEnd, 25))
                ethAmount := shr(176, loaded)
                arguments.offset := add(nonceEnd, 35)
                arguments.length := sub(calldatasize(), add(nonceEnd, 35))
            }
            if (returnBytes) {
                (, bytes memory result) = _executeSessionArbitraryWithValue(
                    signature, nonceValue, deadline, outputContract, ethAmount, arguments
                );
                return result;
            }
            _executeSessionArbitraryWithValue(signature, nonceValue, deadline, outputContract, ethAmount, arguments);
            assembly { return(0x00, 0x00) }
        } else if (functionSelector == bytes1(0x80)) { // executeBatchSessionArbitrary
            uint128 deadline;
            IBatchExecution.Call[] calldata calls;
            assembly {
                let loaded := calldataload(nonceEnd)
                deadline := shr(216, loaded)
                let head := add(nonceEnd, 5)
                calls.length := calldataload(head)
                calls.offset := add(head, 0x20)
            }
            if (returnBytes) {
                (, bytes[] memory result) = _executeBatchSessionArbitrary(signature, nonceValue, deadline, calls);
                return abi.encode(result);
            }
            _executeBatchSessionArbitrary(signature, nonceValue, deadline, calls);
            assembly { return(0x00, 0x00) }
        }

        revert UnsupportedExecutionMode();
    }

    // Internal helpers to centralize common validation logic
    function _requireSelf(bytes32 _hash, bytes calldata _signature, address _expected) internal view {
        if (ECDSA.recoverCalldata(_hash, _signature) != _expected) {
            revert NotSelf();
        }
    }

    function _consumeNonce(uint128 _nonce) internal {
        if (_nonce != state.nonce) {
            revert InvalidNonce();
        }
        unchecked {
            ++state.nonce;
        }
    }

    function _requireCounter(uint128 _counter) internal view {
        if (_counter != state.sessionCounter) {
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
        return value == 0 ? _execute(data[0:65], thisNonce, to, data[133:]) : _executeWithValue(data[0:65], thisNonce, to, value, data[133:]);
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
                   mstore(0x40, add(ptr, 0xa0)) // Update free memory pointer
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
                   mstore(0x40, add(ptr, 0xa0)) // Update free memory pointer
               }
        hash = _hashTypedData(hash);

        _requireSelf(hash, _signature, address(this));
        _consumeNonce(_nonce);
        return _performCallWithValue(_outputContract, _ethAmount, _arguments);
    }

    

    function burnNonce(bytes calldata _signature, uint128 _nonce) external {
               bytes32 hash;
               assembly {
                   let ptr := mload(0x40)
                   mstore(ptr, BURN_NONCE_TYPEHASH)
                   mstore(add(ptr, 0x20), _nonce)
                   hash := keccak256(ptr, 0x40)
                   mstore(0x40, add(ptr, 0x40)) // Update free memory pointer
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
            ++state.nonce;
        }
    }

    /* Session execution */    

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
                   mstore(0x40, add(ptr, 0xa0)) // Update free memory pointer
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

        // Execute the session transaction
        uint256 length = _calls.length;
        bytes[] memory results = new bytes[](length);

        // Cache array access to avoid repeated calldata reads
        for (uint256 i = 0; i < length;) {
            IBatchExecution.Call calldata execution = _calls[i];
            uint256 ethAmount = execution.value;
            address outputContract = execution.to;
            if (outputContract != _outputContract) {
                revert InvalidOutputContract();
            }
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
        if (ECDSA.recoverCalldata(hash, _signature) != address(this)) {
            revert NotSelf();
        }
        unchecked {
            ++state.sessionCounter;
        }
    }

    function burnSessionCounter() external {
        if (msg.sender != address(this) || msg.sender != tx.origin) {
            revert NotSelf();
        }
        unchecked {
            ++state.sessionCounter;
        }
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
        // Forward the raw encoded calls slice to preserve exact preimage
        return _executeBatch(signature, thisNonce, data[81:]);
    }

    function _executeBatch(bytes calldata _signature, uint128 _nonce, bytes calldata _calls)
        internal
        returns (bool, bytes[] memory)
    {
        // Hash the raw encoded calls slice to match the off-chain preimage exactly
        bytes32 executionsHash = keccak256(_calls);
               bytes32 hash;
               assembly {
                   let ptr := mload(0x40)
                   mstore(ptr, BATCH_EXECUTION_TYPEHASH)
                   mstore(add(ptr, 0x20), _nonce)
                   mstore(add(ptr, 0x40), executionsHash)
                   hash := keccak256(ptr, 0x60)
                   mstore(0x40, add(ptr, 0x60)) // Update free memory pointer
               }
        hash = _hashTypedData(hash);
        _requireSelf(hash, _signature, address(this));
        _consumeNonce(_nonce);

        IBatchExecution.Call[] calldata calls;
        uint256 length;
        assembly {
            calls.offset := add(_calls.offset, 0x40)
            calls.length := calldataload(add(_calls.offset, 0x20))
            length := calls.length
        }

        if (length > MAX_BATCH_SIZE) {
            revert BatchSizeExceeded();
        }

        bytes[] memory results = new bytes[](length);
        for (uint256 i = 0; i < length;) {
            IBatchExecution.Call calldata execution = calls[i];
            uint256 ethAmount = execution.value;
            address outputContract = execution.to;
            (bool success, bytes memory result) = ethAmount == 0
                ? outputContract.call(execution.data)
                : outputContract.call{value: ethAmount}(execution.data);
            results[i] = result;
            if (!success) revert ExecutionFailed();
            unchecked { ++i; }
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

    // View functions
    function hashExecution(uint128 _nonce, address _outputContract, uint256 _ethAmount, bytes calldata _arguments)
        external
        view
        returns (bytes32)
    {
        bytes32 argsHash = keccak256(_arguments);
               bytes32 hash;
               assembly {
                   let ptr := mload(0x40)
                   mstore(ptr, EXECUTION_TYPEHASH)
                   mstore(add(ptr, 0x20), _nonce)
                   mstore(add(ptr, 0x40), _outputContract)
                   mstore(add(ptr, 0x60), _ethAmount)
                   mstore(add(ptr, 0x80), argsHash)
                   hash := keccak256(ptr, 0xa0)
                   mstore(0x40, add(ptr, 0xa0)) // Update free memory pointer
               }
        return _hashTypedData(hash);
    }

    function hashBurnNonce(uint128 _nonce) external view returns (bytes32) {
        bytes32 hash;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, BURN_NONCE_TYPEHASH)
            mstore(add(ptr, 0x20), _nonce)
            hash := keccak256(ptr, 0x40)
            mstore(0x40, add(ptr, 0x40)) // Update free memory pointer
        }
        return _hashTypedData(hash);
    }

    function hashSessionExecution(uint128 _counter, uint128 _deadline, address _sender, address _outputContract)
        external
        view
        returns (bytes32)
    {
        bytes32 hash;
        assembly {
            let ptr := mload(0x40)
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
            let ptr := mload(0x40)
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
            let ptr := mload(0x40)
            mstore(ptr, BURN_SESSION_COUNTER_TYPEHASH)
            mstore(add(ptr, 0x20), _counter)
            mstore(add(ptr, 0x40), _sender)
            hash := keccak256(ptr, 0x60)
        }
        return _hashTypedData(hash);
    }

    function hashBatchExecution(uint128 _nonce, IBatchExecution.Call[] calldata _calls)
        external
        view
        returns (bytes32)
    {
        bytes32 executionsHash = keccak256(abi.encode(_calls));
        bytes32 hash;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, BATCH_EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _nonce)
            mstore(add(ptr, 0x40), executionsHash)
            hash := keccak256(ptr, 0x60)
        }
        return _hashTypedData(hash);
    }
}
