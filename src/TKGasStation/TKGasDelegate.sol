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

    bytes32 private constant APPROVE_THEN_EXECUTE_TYPEHASH =
        0xd36c50d64a0a4020f90bce7e65dcb7db1dcf1fffc14bddcf9a1c98ca9faaee62;
    // Original: keccak256("ApproveThenExecute(uint128 nonce,address erc20Contract,address spender,uint256 approveAmount,address outputContract,uint256 ethAmount,bytes arguments)")

    bytes32 private constant BATCH_EXECUTION_TYPEHASH =
        0x55e88ae5d875bf1c64043249314f1ead2a2fcd11e1e423107ef7e93aafc30182;
    // Original: keccak256("BatchExecution(uint128 nonce,Call[] calls)Call(address to,uint256 value,bytes data)")

    bytes32 private constant BURN_NONCE_TYPEHASH = 0x1abb8920e48045adda3ed0ce4be4357be95d4aa21af287280f532fc031584bda;
    // Original: keccak256("BurnNonce(uint128 nonce)")

    bytes32 private constant SESSION_EXECUTION_TYPEHASH =
        0x1c1a5c77ab875e7fe5a91ab8e934d9df1a571b81355d94824440b02d107da50a;
    // Original: keccak256("SessionExecution(uint128 counter,uint32 deadline,address sender,address outputContract)")

    bytes32 private constant ARBITRARY_SESSION_EXECUTION_TYPEHASH =
        0x92edb8c108800040df8284e5de724971aa76a1967778739a97c3d6fc6204b8f7;
    // Original: keccak256("ArbitrarySessionExecution(uint128 counter,uint32 deadline,address sender)")

    bytes32 private constant BURN_SESSION_COUNTER_TYPEHASH =
        0x9e83fc2d99981f8f5e9cca6e9253e48163b75f85c9f1e80235a9380203430d4f;
    // Original: keccak256("BurnSessionCounter(uint128 counter,address sender)")

    // Maximum batch size to prevent griefing attacks
    uint8 public constant MAX_BATCH_SIZE = 50;
    bytes4 private constant APPROVE_SELECTOR = 0x095ea7b3;
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
            bytes calldata outputContractBytes;
            bytes calldata arguments;
            assembly {
                outputContractBytes.offset := nonceEnd
                outputContractBytes.length := 20
                arguments.offset := add(nonceEnd, 20)
                arguments.length := sub(calldatasize(), add(nonceEnd, 20))
            }
            _executeNoValueNoReturn(signature, nonceBytes, outputContractBytes, arguments);
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
            (, bytes memory result) = _executeNoValue(signature, nonceBytes, outputContract, arguments);
            return result;
        } else if (functionSelector == bytes1(0x10)) {
            // executeWithValue no return
            address outputContract;
            uint256 ethAmount;
            bytes calldata arguments;
            assembly {
                let data := calldataload(nonceEnd)
                outputContract := shr(96, data)
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
                let data := calldataload(nonceEnd)
                outputContract := shr(96, data)
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
                deadlineBytes.length := 4
                outputContract := shr(96, calldataload(add(nonceEnd, 9)))
                arguments.offset := add(nonceEnd, 29)
                arguments.length := sub(calldatasize(), add(nonceEnd, 29))
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
                deadlineBytes.length := 4
                outputContract := shr(96, calldataload(add(nonceEnd, 9)))
                arguments.offset := add(nonceEnd, 29)
                arguments.length := sub(calldatasize(), add(nonceEnd, 29))
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
                deadlineBytes.length := 4
                outputContract := shr(96, calldataload(add(nonceEnd, 9)))
                let loaded := calldataload(add(nonceEnd, 24))
                ethAmount := shr(176, loaded)
                arguments.offset := add(nonceEnd, 39)
                arguments.length := sub(calldatasize(), add(nonceEnd, 39))
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
                deadlineBytes.length := 4
                outputContract := shr(96, calldataload(add(nonceEnd, 9)))
                let loaded := calldataload(add(nonceEnd, 24))
                ethAmount := shr(176, loaded)
                arguments.offset := add(nonceEnd, 39)
                arguments.length := sub(calldatasize(), add(nonceEnd, 39))
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
                deadlineBytes.length := 4
                outputContract := shr(96, calldataload(add(nonceEnd, 9)))
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
                deadlineBytes.length := 4
                outputContract := shr(96, calldataload(add(nonceEnd, 9)))
                let head := add(nonceEnd, 41)
                calls.length := calldataload(head)
                calls.offset := add(head, 0x20)
            }
            (, bytes[] memory result) =
                _executeBatchSession(signature, nonceBytes, deadlineBytes, outputContract, calls);
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
                deadlineBytes.length := 4
                outputContract := shr(96, calldataload(add(nonceEnd, 9)))
                arguments.offset := add(nonceEnd, 29)
                arguments.length := sub(calldatasize(), add(nonceEnd, 29))
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
                deadlineBytes.length := 4
                outputContract := shr(96, calldataload(add(nonceEnd, 9)))
                arguments.offset := add(nonceEnd, 29)
                arguments.length := sub(calldatasize(), add(nonceEnd, 29))
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
                deadlineBytes.length := 4
                outputContract := shr(96, calldataload(add(nonceEnd, 9)))
                let loaded := calldataload(add(nonceEnd, 24))
                ethAmount := shr(176, loaded)
                arguments.offset := add(nonceEnd, 39)
                arguments.length := sub(calldatasize(), add(nonceEnd, 39))
            }
            _executeSessionArbitraryWithValue(
                signature, nonceBytes, deadlineBytes, outputContract, ethAmount, arguments
            );
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
                deadlineBytes.length := 4
                outputContract := shr(96, calldataload(add(nonceEnd, 9)))
                let loaded := calldataload(add(nonceEnd, 24))
                ethAmount := shr(176, loaded)
                arguments.offset := add(nonceEnd, 39)
                arguments.length := sub(calldatasize(), add(nonceEnd, 39))
            }
            (, bytes memory result) = _executeSessionArbitraryWithValue(
                signature, nonceBytes, deadlineBytes, outputContract, ethAmount, arguments
            );
            return result;
        } else if (functionSelector == bytes1(0x80)) {
            // executeBatchSessionArbitrary no return
            uint128 counter;
            bytes calldata deadlineBytes;
            IBatchExecution.Call[] calldata calls;
            assembly {
                counter := shr(128, calldataload(nonceBytes.offset))
                deadlineBytes.offset := add(nonceEnd, 5)
                deadlineBytes.length := 4
                let head := add(nonceEnd, 9)
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
                deadlineBytes.length := 4
                let head := add(nonceEnd, 9)
                calls.length := calldataload(head)
                calls.offset := add(head, 0x20)
            }
            (, bytes[] memory result) = _executeBatchSessionArbitrary(signature, nonceBytes, deadlineBytes, calls);
            return abi.encode(result);
        }

        revert UnsupportedExecutionMode();
    }

    // Internal helpers to centralize common validation logic
    function _requireSelf(bytes32 _hash, bytes calldata _signature) internal view {
        if (ECDSA.recoverCalldata(_hash, _signature) != address(this)) {
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
        address to;
        uint256 value;
        assembly {
            // address is 20 bytes immediately after nonce
            to := shr(96, calldataload(add(data.offset, 81)))
            // value is 32 bytes immediately after address
            value := calldataload(add(data.offset, 101))
        }
        return value == 0
            ? _executeNoValue(data[0:65], data[65:81], to, data[133:])
            : _executeWithValue(data[0:65], data[65:81], to, value, data[133:]);
    }

    function executeNoValue(bytes calldata data) external returns (bool, bytes memory) {
        address to;
        assembly {
            // address is 20 bytes immediately after nonce
            to := shr(96, calldataload(add(data.offset, 81)))
        }
        return _executeNoValue(data[0:65], data[65:81], to, data[101:]);
    }

    function approveThenExecute(bytes calldata _data) external returns (bool, bytes memory) {
        // Layout: [signature(65)][nonce(16)][erc20(20)][spender(20)][approveAmount(32)][output(20)][eth(32)][args]
        address to;
        uint256 value;
        assembly {
            to := shr(96, calldataload(add(_data.offset, 153)))
            value := calldataload(add(_data.offset, 173))
        }
        return _approveThenExecute(
            _data[0:65],
            _data[65:81],
            _data[81:101], // erc20 bytes
            _data[101:121],
            _data[121:153],
            to,
            value,
            _data[205:]
        );
    }

    function _approveThenExecute(
        bytes calldata _signature, // 65 bytes
        bytes calldata _nonceBytes, // uint128
        bytes calldata _erc20Bytes, // address (20 bytes)
        bytes calldata _spenderBytes, // address
        bytes calldata _approveAmountBytes, // uint256
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments
    ) internal returns (bool, bytes memory) {
        bytes32 argsHash = keccak256(_arguments);
        bytes32 hash;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, APPROVE_THEN_EXECUTE_TYPEHASH)
            calldatacopy(add(ptr, 0x20), _nonceBytes.offset, 16)
            // erc20 address right-aligned in 32 bytes
            calldatacopy(add(ptr, 0x4c), _erc20Bytes.offset, 20)
            // Write spender (20 bytes right-aligned in 32 bytes)
            calldatacopy(add(ptr, 0x54), _spenderBytes.offset, 20)
            // Write approveAmount (32 bytes)
            calldatacopy(add(ptr, 0x80), _approveAmountBytes.offset, 32)
            mstore(add(ptr, 0xa0), _outputContract)
            mstore(add(ptr, 0xc0), _ethAmount)
            mstore(add(ptr, 0xe0), argsHash)
            // total = 0x100 (256) bytes
            hash := keccak256(ptr, 0x100)
        }
        hash = _hashTypedData(hash);

        _requireSelf(hash, _signature);
        _consumeNonce(_nonceBytes);
        // Build calldata for approve(spender, amount) cheaply in assembly and call token
        assembly {
            let token := shr(96, calldataload(_erc20Bytes.offset))
            let ptr := mload(0x40)
            mstore(ptr, shl(224, 0x095ea7b3)) // IERC20.approve selector
            // Write spender (20 bytes) into the lower 20 bytes of the next 32-byte word
            // Offset 4 + 12 = 16 (0x10)
            calldatacopy(add(ptr, 0x10), _spenderBytes.offset, 20)
            // Write amount (32 bytes) starting at offset 4 + 32 = 0x24
            calldatacopy(add(ptr, 0x24), _approveAmountBytes.offset, 32)
            if iszero(call(gas(), token, 0, ptr, 0x44, 0, 0)) { revert(0, 0) }
        }
        (bool success, bytes memory result) =
            _ethAmount == 0 ? _outputContract.call(_arguments) : _outputContract.call{value: _ethAmount}(_arguments);
        if (success) {
            return (success, result);
        }
        revert ExecutionFailed();
    }

    function _executeNoValueNoReturn(
        bytes calldata _signature,
        bytes calldata _nonceBytes,
        bytes calldata _outputContractBytes,
        bytes calldata _arguments
    ) internal {
        bytes32 argsHash = keccak256(_arguments);
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, EXECUTION_TYPEHASH)
            // Copy nonce bytes directly to memory
            calldatacopy(add(ptr, 0x20), _nonceBytes.offset, 16)
            // Write the 20-byte address (right-aligned) from calldata
            // Load 32 bytes from the start of the address slice, then shift
            // to right-align the 20-byte address in a 32-byte word.
            let raw := calldataload(_outputContractBytes.offset)
            mstore(add(ptr, 0x40), shr(96, raw))
            mstore(add(ptr, 0x60), 0) // ethAmount = 0
            mstore(add(ptr, 0x80), argsHash)
            hash := keccak256(ptr, 0xa0)
            // Defer memory pointer update - will be updated at function end
        }
        hash = _hashTypedData(hash);

        _requireSelf(hash, _signature);
        _consumeNonce(_nonceBytes);
        assembly {
            let outputContract := shr(96, calldataload(_outputContractBytes.offset))
            let ptr := mload(0x40)
            calldatacopy(ptr, _arguments.offset, _arguments.length)
            if iszero(call(gas(), outputContract, 0, ptr, _arguments.length, 0, 0)) { revert(0, 0) }
        }
    }

    function _executeNoValue(
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
            // Defer memory pointer update - will be updated at function end
        }
        hash = _hashTypedData(hash);

        _requireSelf(hash, _signature);
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
            // Defer memory pointer update - will be updated at function end
        }
        hash = _hashTypedData(hash);

        _requireSelf(hash, _signature);
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

        _requireSelf(hash, _signature);
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
            let deadline := shr(224, calldataload(_deadlineBytes.offset))
            if gt(timestamp(), deadline) { revert(0, 0) } // DeadlineExceeded
        }

        address sender = msg.sender;
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, SESSION_EXECUTION_TYPEHASH)
            // Copy counter bytes directly to memory
            calldatacopy(add(ptr, 0x20), _counterBytes.offset, 16)
            // Copy deadline bytes directly to memory
            calldatacopy(add(ptr, 0x40), _deadlineBytes.offset, 4)
            mstore(add(ptr, 0x60), sender)
            mstore(add(ptr, 0x80), _outputContract)
            hash := keccak256(ptr, 0xa0)
            mstore(0x40, add(ptr, 0xa0)) // Update free memory pointer
        }
        hash = _hashTypedData(hash);

        _requireCounter(_counterBytes);
        _requireSelf(hash, _signature);

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
            let deadline := shr(224, calldataload(_deadlineBytes.offset))
            if gt(timestamp(), deadline) { revert(0, 0) } // DeadlineExceeded
        }

        address sender = msg.sender;
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, SESSION_EXECUTION_TYPEHASH)
            // Copy counter bytes directly to memory
            calldatacopy(add(ptr, 0x20), _counterBytes.offset, 16)
            // Copy deadline bytes directly to memory
            calldatacopy(add(ptr, 0x40), _deadlineBytes.offset, 4)
            mstore(add(ptr, 0x60), sender)
            mstore(add(ptr, 0x80), _outputContract)
            hash := keccak256(ptr, 0xa0)
            mstore(0x40, add(ptr, 0xa0)) // Update free memory pointer
        }
        hash = _hashTypedData(hash);

        _requireCounter(_counterBytes);
        _requireSelf(hash, _signature);
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
            let deadline := shr(224, calldataload(_deadlineBytes.offset))
            if gt(timestamp(), deadline) { revert(0, 0) } // DeadlineExceeded
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
            calldatacopy(add(ptr, 0x40), _deadlineBytes.offset, 4)
            mstore(add(ptr, 0x60), sender)
            mstore(add(ptr, 0x80), _outputContract)
            hash := keccak256(ptr, 0xa0)
            mstore(0x40, add(ptr, 0xa0)) // Update free memory pointer
        }
        hash = _hashTypedData(hash);
        _requireCounter(_counterBytes);
        _requireSelf(hash, _signature);

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
            let deadline := shr(224, calldataload(_deadlineBytes.offset))
            if gt(timestamp(), deadline) { revert(0, 0) } // DeadlineExceeded
        }

        address sender = msg.sender;
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, ARBITRARY_SESSION_EXECUTION_TYPEHASH)
            // Copy counter bytes directly to memory
            calldatacopy(add(ptr, 0x20), _counterBytes.offset, 16)
            // Copy deadline bytes directly to memory
            calldatacopy(add(ptr, 0x40), _deadlineBytes.offset, 4)
            mstore(add(ptr, 0x60), sender)
            hash := keccak256(ptr, 0x80)
        }
        hash = _hashTypedData(hash);
        _requireCounter(_counterBytes);
        _requireSelf(hash, _signature);
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
            let deadline := shr(224, calldataload(_deadlineBytes.offset))
            if gt(timestamp(), deadline) { revert(0, 0) } // DeadlineExceeded
        }

        address sender = msg.sender;
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, ARBITRARY_SESSION_EXECUTION_TYPEHASH)
            // Copy counter bytes directly to memory
            calldatacopy(add(ptr, 0x20), _counterBytes.offset, 16)
            // Copy deadline bytes directly to memory
            calldatacopy(add(ptr, 0x40), _deadlineBytes.offset, 4)
            mstore(add(ptr, 0x60), sender)
            hash := keccak256(ptr, 0x80)
        }
        hash = _hashTypedData(hash);
        _requireCounter(_counterBytes);
        _requireSelf(hash, _signature);
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
            let deadline := shr(224, calldataload(_deadlineBytes.offset))
            if gt(timestamp(), deadline) { revert(0, 0) } // DeadlineExceeded
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
            calldatacopy(add(ptr, 0x40), _deadlineBytes.offset, 4)
            mstore(add(ptr, 0x60), sender)
            hash := keccak256(ptr, 0x80)
        }
        hash = _hashTypedData(hash);
        _requireCounter(_counterBytes);
        _requireSelf(hash, _signature);
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
        // Layout: [signature(65)][counter(16)][deadline(4)][sender(20)][output(20)][args]
        bytes calldata signature = data[0:65];
        uint128 counter;
        address output;
        assembly {
            counter := shr(128, calldataload(add(data.offset, 65)))
            output := shr(96, calldataload(add(data.offset, 85)))
        }
        bytes calldata args = data[105:];
        return _executeSession(signature, data[65:81], data[81:85], output, args);
    }

    function executeBatchSession(bytes calldata data) external returns (bool, bytes[] memory) {
        // Layout: [signature(65)][counter(16)][deadline(4)][output(20)][abi.encode(IBatchExecution.Call[])]
        bytes calldata signature = data[0:65];
        uint128 counter;
        address output;
        assembly {
            counter := shr(128, calldataload(add(data.offset, 65)))
            output := shr(96, calldataload(add(data.offset, 85)))
        }

        IBatchExecution.Call[] calldata calls;
        assembly {
            calls.offset := add(data.offset, 105)
            calls.length := calldataload(add(data.offset, 105))
        }
        return _executeBatchSession(signature, data[65:81], data[81:85], output, calls);
    }

    function executeSessionArbitrary(bytes calldata data) external returns (bool, bytes memory) {
        // Layout: [signature(65)][counter(16)][deadline(4)][sender(20)][output(20)][args]
        bytes calldata signature = data[0:65];
        uint128 counter;
        address output;
        assembly {
            counter := shr(128, calldataload(add(data.offset, 65)))
            output := shr(96, calldataload(add(data.offset, 85)))
        }
        bytes calldata args = data[105:];
        return _executeSessionArbitrary(signature, data[65:81], data[81:85], output, args);
    }

    function executeBatchSessionArbitrary(bytes calldata data) external returns (bool, bytes[] memory) {
        // Layout: [signature(65)][counter(16)][deadline(4)][abi.encode(IBatchExecution.Call[])]
        bytes calldata signature = data[0:65];
        uint128 counter;
        assembly {
            counter := shr(128, calldataload(add(data.offset, 65)))
        }
        IBatchExecution.Call[] calldata calls;
        assembly {
            calls.offset := add(data.offset, 85)
            calls.length := calldataload(add(data.offset, 85))
        }
        return _executeBatchSessionArbitrary(signature, data[65:81], data[81:85], calls);
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
        _requireSelf(hash, _signature);
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
