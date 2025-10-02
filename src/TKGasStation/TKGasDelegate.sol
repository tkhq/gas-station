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
        0x79ba6ecfc1c377f07a9fbcb91470ec98ebb102e293d0e8056e4e18a6255a95b9;
    // Original: keccak256("SessionExecution(uint128 counter,uint40 deadline,address sender,address outputContract)")

    bytes32 private constant ARBITRARY_SESSION_EXECUTION_TYPEHASH =
        0x9317d3736e158738d2863e3ca4b0c7bc11053023ebc2db6acf55b8314878e773;
    // Original: keccak256("ArbitrarySessionExecution(uint128 counter,uint40 deadline,address sender)")

    bytes32 private constant BURN_SESSION_COUNTER_TYPEHASH =
        0x9e83fc2d99981f8f5e9cca6e9253e48163b75f85c9f1e80235a9380203430d4f;
    // Original: keccak256("BurnSessionCounter(uint128 counter,address sender)")

    // Maximum batch size to prevent griefing attacks
    uint8 public constant MAX_BATCH_SIZE = 50;
    // Fallback function optimizations
    //uint8 public constant ETH_AMOUNT_MAX_LENGTH_BYTES = 10; // max 1.2m eth if using the fallback function
    //uint8 public constant DEADLINE_MAX_LENGTH_BYTES = 5; // up to ~34 years in seconds
    //uint8 public constant CONTRACT_LENGTH_BYTES = 20; // just for convenience

    State public state;

    constructor() EIP712() {}

    fallback(bytes calldata) external returns (bytes memory) {
        bytes1 functionSelector = bytes1(msg.data[1]);

        bytes calldata signature = msg.data[2:67];
        bytes calldata nonceBytes = msg.data[67:83]; // Always 16 bytes
        uint256 nonceEnd = 83; // Fixed offset after 16-byte nonce

        if (functionSelector == bytes1(0x00)) {
            // execute (no value) no return
            address outputContract;
            bytes calldata arguments;
            assembly {
                outputContract := shr(96, calldataload(nonceEnd))
                arguments.offset := add(nonceEnd, 20)
                arguments.length := sub(calldatasize(), add(nonceEnd, 20))
            }
            _execute(signature, nonceBytes, outputContract, arguments);
            assembly {
                return(0x00, 0x00)
            }
        } else if (functionSelector == bytes1(0x01)) {
            // execute (no value) with return
            address outputContract;
            bytes calldata arguments;
            assembly {
                outputContract := shr(96, calldataload(nonceEnd))
                arguments.offset := add(nonceEnd, 20)
                arguments.length := sub(calldatasize(), add(nonceEnd, 20))
            }
            (, bytes memory result) = _execute(signature, nonceBytes, outputContract, arguments);
            return result;
        } else if (functionSelector == bytes1(0x10)) {
            // executeWithValue no return
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
            _executeWithValue(signature, nonceBytes, outputContract, ethAmount, arguments);
            assembly {
                return(0x00, 0x00)
            }
        } else if (functionSelector == bytes1(0x11)) {
            // executeWithValue with return
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
            (, bytes memory result) = _executeWithValue(signature, nonceBytes, outputContract, ethAmount, arguments);
            return result;
        } else if (functionSelector == bytes1(0x20)) {
            // executeBatch no return
            _executeBatch(signature, nonceBytes, msg.data[nonceEnd:]);
            assembly {
                return(0x00, 0x00)
            }
        } else if (functionSelector == bytes1(0x21)) {
            // executeBatch with return
            (, bytes[] memory result) = _executeBatch(signature, nonceBytes, msg.data[nonceEnd:]);
            return abi.encode(result);
        } else if (functionSelector == bytes1(0x30)) {
            // executeSession no return
            uint128 counter;
            bytes calldata deadlineBytes;
            address outputContract;
            bytes calldata arguments;
            assembly {
                counter := shr(128, calldataload(nonceBytes.offset))
                deadlineBytes.offset := add(nonceEnd, 5)
                deadlineBytes.length := 5
                outputContract := shr(96, calldataload(add(nonceEnd, 10)))
                arguments.offset := add(nonceEnd, 30)
                arguments.length := sub(calldatasize(), add(nonceEnd, 30))
            }
            _executeSession(signature, nonceBytes, deadlineBytes, outputContract, arguments);
            assembly {
                return(0x00, 0x00)
            }
        } else if (functionSelector == bytes1(0x31)) {
            // executeSession with return
            uint128 counter;
            bytes calldata deadlineBytes;
            address outputContract;
            bytes calldata arguments;
            assembly {
                counter := shr(128, calldataload(nonceBytes.offset))
                deadlineBytes.offset := add(nonceEnd, 5)
                deadlineBytes.length := 5
                outputContract := shr(96, calldataload(add(nonceEnd, 10)))
                arguments.offset := add(nonceEnd, 30)
                arguments.length := sub(calldatasize(), add(nonceEnd, 30))
            }
            (, bytes memory result) = _executeSession(signature, nonceBytes, deadlineBytes, outputContract, arguments);
            return result;
        } else if (functionSelector == bytes1(0x40)) {
            // executeSessionWithValue no return
            uint128 counter;
            bytes calldata deadlineBytes;
            address outputContract;
            uint256 ethAmount;
            bytes calldata arguments;
            assembly {
                counter := shr(128, calldataload(nonceBytes.offset))
                deadlineBytes.offset := add(nonceEnd, 5)
                deadlineBytes.length := 5
                outputContract := shr(96, calldataload(add(nonceEnd, 10)))
                let loaded := calldataload(add(nonceEnd, 25))
                ethAmount := shr(176, loaded)
                arguments.offset := add(nonceEnd, 40)
                arguments.length := sub(calldatasize(), add(nonceEnd, 40))
            }
            _executeSessionWithValue(signature, nonceBytes, deadlineBytes, outputContract, ethAmount, arguments);
            assembly {
                return(0x00, 0x00)
            }
        } else if (functionSelector == bytes1(0x41)) {
            // executeSessionWithValue with return
            uint128 counter;
            bytes calldata deadlineBytes;
            address outputContract;
            uint256 ethAmount;
            bytes calldata arguments;
            assembly {
                counter := shr(128, calldataload(nonceBytes.offset))
                deadlineBytes.offset := add(nonceEnd, 5)
                deadlineBytes.length := 5
                outputContract := shr(96, calldataload(add(nonceEnd, 10)))
                let loaded := calldataload(add(nonceEnd, 25))
                ethAmount := shr(176, loaded)
                arguments.offset := add(nonceEnd, 40)
                arguments.length := sub(calldatasize(), add(nonceEnd, 40))
            }
            (, bytes memory result) =
                _executeSessionWithValue(signature, nonceBytes, deadlineBytes, outputContract, ethAmount, arguments);
            return result;
        } else if (functionSelector == bytes1(0x50)) {
            // executeBatchSession no return
            uint128 counter;
            bytes calldata deadlineBytes;
            address outputContract;
            IBatchExecution.Call[] calldata calls;
            assembly {
                counter := shr(128, calldataload(nonceBytes.offset))
                deadlineBytes.offset := add(nonceEnd, 5)
                deadlineBytes.length := 5
                outputContract := shr(96, calldataload(add(nonceEnd, 10)))
                let head := add(nonceEnd, 41)
                calls.length := calldataload(head)
                calls.offset := add(head, 0x20)
            }
            _executeBatchSession(signature, nonceBytes, deadlineBytes, outputContract, calls);
            assembly {
                return(0x00, 0x00)
            }
        } else if (functionSelector == bytes1(0x51)) {
            // executeBatchSession with return
            uint128 counter;
            bytes calldata deadlineBytes;
            address outputContract;
            IBatchExecution.Call[] calldata calls;
            assembly {
                counter := shr(128, calldataload(nonceBytes.offset))
                deadlineBytes.offset := add(nonceEnd, 5)
                deadlineBytes.length := 5
                outputContract := shr(96, calldataload(add(nonceEnd, 10)))
                let head := add(nonceEnd, 41)
                calls.length := calldataload(head)
                calls.offset := add(head, 0x20)
            }
            (, bytes[] memory result) = _executeBatchSession(signature, nonceBytes, deadlineBytes, outputContract, calls);
            return abi.encode(result);
        } else if (functionSelector == bytes1(0x60)) {
            // executeSessionArbitrary no return
            uint128 counter;
            bytes calldata deadlineBytes;
            address outputContract;
            bytes calldata arguments;
            assembly {
                counter := shr(128, calldataload(nonceBytes.offset))
                deadlineBytes.offset := add(nonceEnd, 5)
                deadlineBytes.length := 5
                outputContract := shr(96, calldataload(add(nonceEnd, 10)))
                arguments.offset := add(nonceEnd, 30)
                arguments.length := sub(calldatasize(), add(nonceEnd, 30))
            }
            _executeSessionArbitrary(signature, nonceBytes, deadlineBytes, outputContract, arguments);
            assembly {
                return(0x00, 0x00)
            }
        } else if (functionSelector == bytes1(0x61)) {
            // executeSessionArbitrary with return
            uint128 counter;
            bytes calldata deadlineBytes;
            address outputContract;
            bytes calldata arguments;
            assembly {
                counter := shr(128, calldataload(nonceBytes.offset))
                deadlineBytes.offset := add(nonceEnd, 5)
                deadlineBytes.length := 5
                outputContract := shr(96, calldataload(add(nonceEnd, 10)))
                arguments.offset := add(nonceEnd, 30)
                arguments.length := sub(calldatasize(), add(nonceEnd, 30))
            }
            (, bytes memory result) =
                _executeSessionArbitrary(signature, nonceBytes, deadlineBytes, outputContract, arguments);
            return result;
        } else if (functionSelector == bytes1(0x70)) {
            // executeSessionArbitraryWithValue no return
            uint128 counter;
            bytes calldata deadlineBytes;
            address outputContract;
            uint256 ethAmount;
            bytes calldata arguments;
            assembly {
                counter := shr(128, calldataload(nonceBytes.offset))
                deadlineBytes.offset := add(nonceEnd, 5)
                deadlineBytes.length := 5
                outputContract := shr(96, calldataload(add(nonceEnd, 10)))
                let loaded := calldataload(add(nonceEnd, 25))
                ethAmount := shr(176, loaded)
                arguments.offset := add(nonceEnd, 40)
                arguments.length := sub(calldatasize(), add(nonceEnd, 40))
            }
            _executeSessionArbitraryWithValue(signature, nonceBytes, deadlineBytes, outputContract, ethAmount, arguments);
            assembly {
                return(0x00, 0x00)
            }
        } else if (functionSelector == bytes1(0x71)) {
            // executeSessionArbitraryWithValue with return
            uint128 counter;
            bytes calldata deadlineBytes;
            address outputContract;
            uint256 ethAmount;
            bytes calldata arguments;
            assembly {
                counter := shr(128, calldataload(nonceBytes.offset))
                deadlineBytes.offset := add(nonceEnd, 5)
                deadlineBytes.length := 5
                outputContract := shr(96, calldataload(add(nonceEnd, 10)))
                let loaded := calldataload(add(nonceEnd, 25))
                ethAmount := shr(176, loaded)
                arguments.offset := add(nonceEnd, 40)
                arguments.length := sub(calldatasize(), add(nonceEnd, 40))
            }
            (, bytes memory result) =
                _executeSessionArbitraryWithValue(signature, nonceBytes, deadlineBytes, outputContract, ethAmount, arguments);
            return result;
        } else if (functionSelector == bytes1(0x80)) {
            // executeBatchSessionArbitrary no return
            uint128 counter;
            bytes calldata deadlineBytes;
            IBatchExecution.Call[] calldata calls;
            assembly {
                counter := shr(128, calldataload(nonceBytes.offset))
                deadlineBytes.offset := add(nonceEnd, 5)
                deadlineBytes.length := 5
                let head := add(nonceEnd, 10)
                calls.length := calldataload(head)
                calls.offset := add(head, 0x20)
            }
            _executeBatchSessionArbitrary(signature, nonceBytes, deadlineBytes, calls);
            assembly {
                return(0x00, 0x00)
            }
        } else if (functionSelector == bytes1(0x81)) {
            // executeBatchSessionArbitrary with return
            uint128 counter;
            bytes calldata deadlineBytes;
            IBatchExecution.Call[] calldata calls;
            assembly {
                counter := shr(128, calldataload(nonceBytes.offset))
                deadlineBytes.offset := add(nonceEnd, 5)
                deadlineBytes.length := 5
                let head := add(nonceEnd, 10)
                calls.length := calldataload(head)
                calls.offset := add(head, 0x20)
            }
            (, bytes[] memory result) = _executeBatchSessionArbitrary(signature, nonceBytes, deadlineBytes, calls);
            return abi.encode(result);
        }

        revert UnsupportedExecutionMode();
    }

    // Internal helpers to centralize common validation logic
    function _requireSelf(bytes32 _hash, bytes calldata _signature, address _expected) internal view {
        if (ECDSA.recoverCalldata(_hash, _signature) != _expected) {
            revert NotSelf();
        }
    }

    function _consumeNonce(bytes calldata _nonceBytes) internal {
        // Compare raw calldata bytes with current nonce
        uint128 currentNonce = state.nonce;
        uint128 nonceValue;
        assembly {
            nonceValue := shr(128, calldataload(_nonceBytes.offset))
        }
        if (nonceValue != currentNonce) {
            revert InvalidNonce();
        }
        unchecked {
            ++state.nonce;
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

    function _requireCounter(bytes calldata _counterBytes) internal view {
        // Parse counter from calldata and compare
        uint128 counterValue;
        assembly {
            counterValue := shr(128, calldataload(_counterBytes.offset))
        }
        if (counterValue != state.sessionCounter) {
            revert InvalidCounter();
        }
    }

    function _requireCounter(uint128 _counter) internal view {
        if (_counter != state.sessionCounter) {
            revert InvalidCounter();
        }
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
        return value == 0
            ? _execute(data[0:65], data[65:81], to, data[133:])
            : _executeWithValue(data[0:65], data[65:81], to, value, data[133:]);
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
        return _execute(data[0:65], data[65:81], to, data[101:]);
    }

    function _execute(
        bytes calldata _signature,
        bytes calldata _nonceBytes,
        address _outputContract,
        bytes calldata _arguments
    ) internal returns (bool, bytes memory) {
        bytes32 argsHash = keccak256(_arguments);
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, EXECUTION_TYPEHASH)
            // Copy nonce bytes directly to memory
            calldatacopy(add(ptr, 0x20), _nonceBytes.offset, 16)
            mstore(add(ptr, 0x40), _outputContract)
            mstore(add(ptr, 0x60), 0) // ethAmount = 0
            mstore(add(ptr, 0x80), argsHash)
            hash := keccak256(ptr, 0xa0)
            mstore(0x40, add(ptr, 0xa0)) // Update free memory pointer
        }
        hash = _hashTypedData(hash);

        _requireSelf(hash, _signature, address(this));
        _consumeNonce(_nonceBytes);
        (bool success, bytes memory result) = _outputContract.call(_arguments);
        if (success) {
            return (success, result);
        }
        revert ExecutionFailed();
    }

    function _executeWithValue(
        bytes calldata _signature,
        bytes calldata _nonceBytes,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments
    ) internal returns (bool, bytes memory) {
        bytes32 argsHash = keccak256(_arguments);
        bytes32 hash; // all this assembly to avoid using abi.encode
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, EXECUTION_TYPEHASH)
            // Copy nonce bytes directly to memory
            calldatacopy(add(ptr, 0x20), _nonceBytes.offset, 16)
            mstore(add(ptr, 0x40), _outputContract)
            mstore(add(ptr, 0x60), _ethAmount)
            mstore(add(ptr, 0x80), argsHash)
            hash := keccak256(ptr, 0xa0)
            mstore(0x40, add(ptr, 0xa0)) // Update free memory pointer
        }
        hash = _hashTypedData(hash);

        _requireSelf(hash, _signature, address(this));
        _consumeNonce(_nonceBytes);
        (bool success, bytes memory result) = _outputContract.call{value: _ethAmount}(_arguments);
        if (success) {
            return (success, result);
        }
        revert ExecutionFailed();
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
        bytes calldata _counterBytes,
        bytes calldata _deadlineBytes,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments
    ) internal returns (bool, bytes memory) {
        // Check if deadline has passed using calldata
        assembly {
            let deadline := shr(216, calldataload(_deadlineBytes.offset))
            if gt(timestamp(), deadline) {
                revert(0, 0) // DeadlineExceeded
            }
        }

        address sender = msg.sender;
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, SESSION_EXECUTION_TYPEHASH)
            // Copy counter bytes directly to memory
            calldatacopy(add(ptr, 0x20), _counterBytes.offset, 16)
            // Copy deadline bytes directly to memory
            calldatacopy(add(ptr, 0x40), _deadlineBytes.offset, 5)
            mstore(add(ptr, 0x60), sender)
            mstore(add(ptr, 0x80), _outputContract)
            hash := keccak256(ptr, 0xa0)
            mstore(0x40, add(ptr, 0xa0)) // Update free memory pointer
        }
        hash = _hashTypedData(hash);

        _requireCounter(_counterBytes);
        _requireSelf(hash, _signature, address(this));

        (bool success, bytes memory result) = _outputContract.call{value: _ethAmount}(_arguments);

        if (success) {
            return (success, result);
        }
        revert ExecutionFailed();
    }

    function _executeSession(
        bytes calldata _signature,
        bytes calldata _counterBytes,
        bytes calldata _deadlineBytes,
        address _outputContract,
        bytes calldata _arguments
    ) internal returns (bool, bytes memory) {
        // Check if deadline has passed using calldata
        assembly {
            let deadline := shr(216, calldataload(_deadlineBytes.offset))
            if gt(timestamp(), deadline) {
                revert(0, 0) // DeadlineExceeded
            }
        }

        address sender = msg.sender;
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, SESSION_EXECUTION_TYPEHASH)
            // Copy counter bytes directly to memory
            calldatacopy(add(ptr, 0x20), _counterBytes.offset, 16)
            // Copy deadline bytes directly to memory
            calldatacopy(add(ptr, 0x40), _deadlineBytes.offset, 5)
            mstore(add(ptr, 0x60), sender)
            mstore(add(ptr, 0x80), _outputContract)
            hash := keccak256(ptr, 0xa0)
            mstore(0x40, add(ptr, 0xa0)) // Update free memory pointer
        }
        hash = _hashTypedData(hash);

        _requireCounter(_counterBytes);
        _requireSelf(hash, _signature, address(this));
        // Execute the session transaction (counter does NOT increment for session)
        (bool success, bytes memory result) = _outputContract.call(_arguments);
        if (success) {
            return (success, result);
        }
        revert ExecutionFailed();
    }

    function _executeBatchSession(
        bytes calldata _signature,
        bytes calldata _counterBytes,
        bytes calldata _deadlineBytes,
        address _outputContract,
        IBatchExecution.Call[] calldata _calls
    ) internal returns (bool, bytes[] memory) {
        // Check if deadline has passed using calldata
        assembly {
            let deadline := shr(216, calldataload(_deadlineBytes.offset))
            if gt(timestamp(), deadline) {
                revert(0, 0) // DeadlineExceeded
            }
        }
        if (_calls.length > MAX_BATCH_SIZE) {
            revert BatchSizeExceeded();
        }

        address sender = msg.sender;
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, SESSION_EXECUTION_TYPEHASH)
            // Copy counter bytes directly to memory
            calldatacopy(add(ptr, 0x20), _counterBytes.offset, 16)
            // Copy deadline bytes directly to memory
            calldatacopy(add(ptr, 0x40), _deadlineBytes.offset, 5)
            mstore(add(ptr, 0x60), sender)
            mstore(add(ptr, 0x80), _outputContract)
            hash := keccak256(ptr, 0xa0)
            mstore(0x40, add(ptr, 0xa0)) // Update free memory pointer
        }
        hash = _hashTypedData(hash);
        _requireCounter(_counterBytes);
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

    function _executeSessionArbitrary(
        bytes calldata _signature,
        bytes calldata _counterBytes,
        bytes calldata _deadlineBytes,
        address _outputContract,
        bytes calldata _arguments
    ) internal returns (bool, bytes memory) {
        // Check if deadline has passed using calldata
        assembly {
            let deadline := shr(216, calldataload(_deadlineBytes.offset))
            if gt(timestamp(), deadline) {
                revert(0, 0) // DeadlineExceeded
            }
        }

        address sender = msg.sender;
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, ARBITRARY_SESSION_EXECUTION_TYPEHASH)
            // Copy counter bytes directly to memory
            calldatacopy(add(ptr, 0x20), _counterBytes.offset, 16)
            // Copy deadline bytes directly to memory
            calldatacopy(add(ptr, 0x40), _deadlineBytes.offset, 5)
            mstore(add(ptr, 0x60), sender)
            hash := keccak256(ptr, 0x80)
        }
        hash = _hashTypedData(hash);
        _requireCounter(_counterBytes);
        _requireSelf(hash, _signature, address(this));
        // Execute the session transaction
        (bool success, bytes memory result) = _outputContract.call(_arguments);
        if (success) {
            return (success, result);
        }
        revert ExecutionFailed();
    }

    function _executeSessionArbitraryWithValue(
        bytes calldata _signature,
        bytes calldata _counterBytes,
        bytes calldata _deadlineBytes,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments
    ) internal returns (bool, bytes memory) {
        // Check if deadline has passed using calldata
        assembly {
            let deadline := shr(216, calldataload(_deadlineBytes.offset))
            if gt(timestamp(), deadline) {
                revert(0, 0) // DeadlineExceeded
            }
        }

        address sender = msg.sender;
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, ARBITRARY_SESSION_EXECUTION_TYPEHASH)
            // Copy counter bytes directly to memory
            calldatacopy(add(ptr, 0x20), _counterBytes.offset, 16)
            // Copy deadline bytes directly to memory
            calldatacopy(add(ptr, 0x40), _deadlineBytes.offset, 5)
            mstore(add(ptr, 0x60), sender)
            hash := keccak256(ptr, 0x80)
        }
        hash = _hashTypedData(hash);
        _requireCounter(_counterBytes);
        _requireSelf(hash, _signature, address(this));
        // Execute the session transaction
        (bool success, bytes memory result) = _outputContract.call{value: _ethAmount}(_arguments);
        if (success) {
            return (success, result);
        }
        revert ExecutionFailed();
    }

    function _executeBatchSessionArbitrary(
        bytes calldata _signature,
        bytes calldata _counterBytes,
        bytes calldata _deadlineBytes, // Changed from uint128
        IBatchExecution.Call[] calldata _calls
    ) internal returns (bool, bytes[] memory) {
        // Check if deadline has passed using calldata
        assembly {
            let deadline := shr(216, calldataload(_deadlineBytes.offset))
            if gt(timestamp(), deadline) {
                revert(0, 0) // DeadlineExceeded
            }
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
            // Copy counter bytes directly to memory
            calldatacopy(add(ptr, 0x20), _counterBytes.offset, 16)
            // Copy deadline bytes directly to memory
            calldatacopy(add(ptr, 0x40), _deadlineBytes.offset, 5)
            mstore(add(ptr, 0x60), sender)
            hash := keccak256(ptr, 0x80)
        }
        hash = _hashTypedData(hash);
        _requireCounter(_counterBytes);
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

    function burnSessionCounter(bytes calldata _signature, uint128 _counter, address _sender) external {
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, BURN_SESSION_COUNTER_TYPEHASH)
            mstore(add(ptr, 0x20), _counter)
            mstore(add(ptr, 0x40), _sender)
            hash := keccak256(ptr, 0x60)
            mstore(0x40, add(ptr, 0x60)) // Update free memory pointer
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
        // Layout: [signature(65)][counter(16)][deadline(5)][sender(20)][output(20)][args]
        bytes calldata signature = data[0:65];
        uint128 counter;
        address output;
        assembly {
            counter := shr(128, calldataload(add(data.offset, 65)))
            output := shr(96, calldataload(add(data.offset, 86)))
        }
        bytes calldata args = data[106:];
        return _executeSession(signature, data[65:81], data[81:86], output, args);
    }

    function executeBatchSession(bytes calldata data) external returns (bool, bytes[] memory) {
        // Layout: [signature(65)][counter(16)][deadline(5)][output(20)][abi.encode(IBatchExecution.Call[])]
        bytes calldata signature = data[0:65];
        uint128 counter;
        address output;
        assembly {
            counter := shr(128, calldataload(add(data.offset, 65)))
            output := shr(96, calldataload(add(data.offset, 86)))
        }

        IBatchExecution.Call[] calldata calls;
        assembly {
            calls.offset := add(data.offset, 106)
            calls.length := calldataload(add(data.offset, 106))
        }
        return _executeBatchSession(signature, data[65:81], data[81:86], output, calls);
    }

    function executeSessionArbitrary(bytes calldata data) external returns (bool, bytes memory) {
        // Layout: [signature(65)][counter(16)][deadline(5)][sender(20)][output(20)][args]
        bytes calldata signature = data[0:65];
        uint128 counter;
        address output;
        assembly {
            counter := shr(128, calldataload(add(data.offset, 65)))
            output := shr(96, calldataload(add(data.offset, 86)))
        }
        bytes calldata args = data[106:];
        return _executeSessionArbitrary(signature, data[65:81], data[81:86], output, args);
    }

    function executeBatchSessionArbitrary(bytes calldata data) external returns (bool, bytes[] memory) {
        // Layout: [signature(65)][counter(16)][deadline(5)][abi.encode(IBatchExecution.Call[])]
        bytes calldata signature = data[0:65];
        uint128 counter;
        assembly {
            counter := shr(128, calldataload(add(data.offset, 65)))
        }
        IBatchExecution.Call[] calldata calls;
        assembly {
            calls.offset := add(data.offset, 86)
            calls.length := calldataload(add(data.offset, 86))
        }
        return _executeBatchSessionArbitrary(signature, data[65:81], data[81:86], calls);
    }

    function executeBatch(bytes calldata data) external returns (bool, bytes[] memory) {
        // Layout: [signature(65)][nonce(16)][abi.encode(IBatchExecution.Call[])]
        bytes calldata signature = data[0:65];
        uint128 thisNonce;
        assembly {
            thisNonce := shr(128, calldataload(add(data.offset, 65)))
        }
        // Forward the raw encoded calls slice to preserve exact preimage
        return _executeBatch(signature, data[65:81], data[81:]);
    }

    function _executeBatch(bytes calldata _signature, bytes calldata _nonceBytes, bytes calldata _calls)
        internal
        returns (bool, bytes[] memory)
    {
        // Hash the raw encoded calls slice to match the off-chain preimage exactly
        bytes32 executionsHash = keccak256(_calls);
        bytes32 hash;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, BATCH_EXECUTION_TYPEHASH)
            // Copy nonce bytes directly to memory
            calldatacopy(add(ptr, 0x20), _nonceBytes.offset, 16)
            mstore(add(ptr, 0x40), executionsHash)
            hash := keccak256(ptr, 0x60)
            mstore(0x40, add(ptr, 0x60)) // Update free memory pointer
        }
        hash = _hashTypedData(hash);
        _requireSelf(hash, _signature, address(this));
        _consumeNonce(_nonceBytes);

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
            mstore(0x40, add(ptr, 0xa0)) // Update free memory pointer
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
            mstore(0x40, add(ptr, 0x80)) // Update free memory pointer
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
            mstore(0x40, add(ptr, 0x60)) // Update free memory pointer
        }
        return _hashTypedData(hash);
    }

    function hashBatchExecution(uint128 _nonce, IBatchExecution.Call[] calldata _calls)
        external
        view
        returns (bytes32)
    {
        // Keep abi.encode for complex types (abi.encodePacked doesn't support Call[] arrays)
        bytes32 executionsHash = keccak256(abi.encode(_calls));
        bytes32 hash;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, BATCH_EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _nonce)
            mstore(add(ptr, 0x40), executionsHash)
            hash := keccak256(ptr, 0x60)
            mstore(0x40, add(ptr, 0x60)) // Update free memory pointer
        }
        return _hashTypedData(hash);
    }
}
