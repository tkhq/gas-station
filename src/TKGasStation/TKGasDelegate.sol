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
/// @dev Implements EIP-712 for typed structured data signing, supporting multiple execution modes including standard execution, batch execution, sessions, and ERC20 approve-then-execute patterns
contract TKGasDelegate is EIP712, IERC1155Receiver, IERC721Receiver, IERC1721, ITKGasDelegate {
    error BatchSizeInvalid();
    error DeadlineExceeded();
    error InvalidToContract();
    error InvalidNonce();
    error InvalidCounter();
    error NotSelf();
    error ExecutionFailed();
    error UnsupportedExecutionMode();
    error ApprovalFailed();
    error ApprovalTo0Failed();
    error ApprovalReturnFalse();
    error InvalidOffset();

    error Debug(bytes32 a, bytes32 b);

    bytes4 internal constant DEADLINE_EXCEEDED_SELECTOR = 0x559895a3;
    bytes4 internal constant APPROVAL_FAILED_SELECTOR = 0x8164f842;
    bytes4 internal constant APPROVAL_TO_0_FAILED_SELECTOR = 0xe12092fc;
    bytes4 internal constant APPROVAL_RETURN_FALSE_SELECTOR = 0xf572481d;
    bytes4 internal constant BATCH_SIZE_INVALID_SELECTOR = 0xde21ae18;
    bytes4 internal constant INVALID_OFFSET_SELECTOR = 0x01da1572;
    bytes4 internal constant ERC1271_MAGIC_VALUE = 0x1626ba7e;
    uint8 public constant MAX_BATCH_SIZE = 20;

    bytes32 internal constant EXECUTION_TYPEHASH = 0x06bb52ccb5d61c4f9c5baafc0affaba32c4d02864c91221ad411291324aeea2e;
    // keccak256("Execution(uint128 nonce,uint32 deadline,address to,uint256 value,bytes data)")

    bytes32 internal constant APPROVE_THEN_EXECUTE_TYPEHASH =
        0x321d2e8c030c2c64001a1895d0f865dd0dc361666bd775ccb835b1a8bc2d41e3;
    // keccak256("ApproveThenExecute(uint128 nonce,uint32 deadline,address erc20Contract,address spender,uint256 approveAmount,address to,uint256 value,bytes data)")

    bytes32 internal constant BATCH_EXECUTION_TYPEHASH =
        0x14007e8c5dd696e52899952d0c28098ab95c056d082adc0d757f91c1306c7f55;
    // keccak256("BatchExecution(uint128 nonce,uint32 deadline,Call[] calls)Call(address to,uint256 value,bytes data)")

    bytes32 internal constant CALL_TYPEHASH = 0x9085b19ea56248c94d86174b3784cfaaa8673d1041d6441f61ff52752dac8483;
    // keccak256("Call(address to,uint256 value,bytes data)")

    bytes32 internal constant BURN_NONCE_TYPEHASH = 0x1abb8920e48045adda3ed0ce4be4357be95d4aa21af287280f532fc031584bda;
    // keccak256("BurnNonce(uint128 nonce)")

    bytes32 internal constant SESSION_EXECUTION_TYPEHASH =
        0xfe77dfae033808a0d3fd8ba43e104e84622b2d23bd43e92d96df863e280843e6;
    // keccak256("SessionExecution(uint128 counter,uint32 deadline,address sender,address to)")

    bytes32 internal constant ARBITRARY_SESSION_EXECUTION_TYPEHASH =
        0x37c1343675452b4c8f9477fbedff7bcc1e7fa8b3bc97a1e58d4e371c86bd64bb;
    // keccak256("ArbitrarySessionExecution(uint128 counter,uint32 deadline,address sender)")

    bytes32 internal constant BURN_SESSION_COUNTER_TYPEHASH =
        0x601e2106a9a69d50c3489343bfc805c6ad1b051e27f87c20ed3735e4fdbb0826;
    // keccak256("BurnSessionCounter(uint128 counter)")

    /// @custom:storage-location erc7201:TKGasDelegate.state
    struct State {
        uint128 nonce;
        mapping(bytes16 => bool) expiredSessionCounters;
        mapping(uint64 => uint64) nonces;
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

    /// @notice Returns the nonce for a given prefix
    /// @dev Supports both standard nonces (prefix 0) and prefix-based nonces. When prefix is 0, returns the standard nonce. When prefix is non-zero, returns a combined value where the prefix occupies the upper 64 bits and the prefix-specific nonce value occupies the lower 64 bits
    /// @param _prefix The nonce prefix. Use 0 for the standard nonce, or a non-zero value for prefix-based nonces
    /// @return The nonce value. For prefix 0, returns the standard nonce. For non-zero prefixes, returns (prefix << 64) | nonceValue
    function getNonce(uint64 _prefix) external view returns (uint128) {
        if (_prefix == 0) {
            return _getStateStorage().nonce;
        } else {
            uint64 nonceValue = _getStateStorage().nonces[_prefix];
            return (uint128(_prefix) << 64) | uint128(nonceValue);
        }
    }

    /// @notice Checks if a session counter has been burned/expired
    /// @dev Session counters can be invalidated to revoke session permissions
    /// @param _counter The session counter to check
    /// @return true if the counter has been burned, false otherwise
    function checkSessionCounterExpired(uint128 _counter) external view returns (bool) {
        return _getStateStorage().expiredSessionCounters[bytes16(_counter)];
    }

    /// @notice Initializes the TKGasDelegate contract
    /// @dev Sets up EIP-712 domain separator with name "TKGasDelegate" and version "1"
    constructor() EIP712() {}

    fallback(bytes calldata) external returns (bytes memory) {
        bytes1 functionSelector = bytes1(msg.data[1]);

        bytes calldata signature = msg.data[2:67];
        bytes calldata nonceBytes = msg.data[67:83]; // Always 16 bytes - can also be the counter
        bytes calldata deadlineBytes = msg.data[83:87]; // 4 bytes deadline
        uint256 nonceEnd = 87; // Fixed offset after 16-byte nonce + 4-byte deadline

        // NO RETURN PATHS (0xX0) - Checked first
        if (functionSelector == bytes1(0x00)) {
            // execute (no return) - handles both with and without value
            bytes calldata outputContractBytes;
            uint256 ethAmount;
            bytes calldata arguments;
            assembly ("memory-safe") {
                outputContractBytes.offset := nonceEnd
                outputContractBytes.length := 20
                let loaded := calldataload(add(nonceEnd, 20))
                ethAmount := shr(176, loaded)
                arguments.offset := add(nonceEnd, 30)
                arguments.length := sub(calldatasize(), add(nonceEnd, 30))
            }
            if (ethAmount == 0) {
                address outputContract;
                assembly ("memory-safe") {
                    outputContract := shr(96, calldataload(nonceEnd))
                }
                _executeNoValueNoReturn(signature, nonceBytes, deadlineBytes, outputContract, arguments);
            } else {
                address outputContract;
                assembly ("memory-safe") {
                    outputContract := shr(96, calldataload(nonceEnd))
                }
                _executeWithValueNoReturn(signature, nonceBytes, deadlineBytes, outputContract, ethAmount, arguments);
            }
            assembly ("memory-safe") {
                return(0x00, 0x00)
            }
        } else if (functionSelector == bytes1(0x10)) {
            // approveThenExecute no return
            address erc20;
            address spender;
            uint256 approveAmount;
            address outputContract;
            uint256 ethAmount;
            assembly ("memory-safe") {
                erc20 := shr(96, calldataload(nonceEnd))
                spender := shr(96, calldataload(add(nonceEnd, 20)))
                approveAmount := calldataload(add(nonceEnd, 40))
                outputContract := shr(96, calldataload(add(nonceEnd, 72)))
                let loaded := calldataload(add(nonceEnd, 92))
                ethAmount := shr(176, loaded) // 10 bytes, right-aligned
            }
            _approveThenExecuteNoReturnWithParams(
                signature,
                nonceBytes,
                deadlineBytes,
                erc20,
                spender,
                approveAmount,
                outputContract,
                ethAmount,
                msg.data[nonceEnd + 102:] //arguments
            );
            assembly ("memory-safe") {
                return(0x00, 0x00)
            }
        } else if (functionSelector == bytes1(0x20)) {
            // executeBatch no return
            _executeBatchNoReturn(signature, nonceBytes, deadlineBytes, msg.data[nonceEnd:]);
            assembly ("memory-safe") {
                return(0x00, 0x00)
            }
        } else if (functionSelector == bytes1(0x30)) {
            uint256 ethAmount;
            bytes calldata arguments;
            assembly ("memory-safe") {
                let w := calldataload(107) // Updated offset for deadline
                ethAmount := shr(176, w) // (32-10)*8
                arguments.offset := add(107, 10) // Skip the 10-byte ethAmount
                arguments.length := sub(calldatasize(), add(107, 10))
            }
            _executeSessionWithValueNoReturn(
                signature, nonceBytes, deadlineBytes, msg.data[nonceEnd:nonceEnd + 20], ethAmount, arguments
            );
            assembly ("memory-safe") {
                return(0x00, 0x00)
            }
        } else if (functionSelector == bytes1(0x40)) {
            // executeBatchSession no return
            IBatchExecution.Call[] calldata calls;
            assembly ("memory-safe") {
                calls.offset := add(107, 0x40) // Updated offset for deadline
                calls.length := calldataload(add(107, 0x20))
            }
            _executeBatchSessionNoReturn(signature, nonceBytes, deadlineBytes, msg.data[nonceEnd:nonceEnd + 20], calls);
            assembly ("memory-safe") {
                return(0x00, 0x00)
            }
        } else if (functionSelector == bytes1(0x50)) {
            // executeSessionArbitraryWithValue no return
            uint256 ethAmount;
            bytes calldata arguments;
            assembly ("memory-safe") {
                let loaded := calldataload(107) // Updated offset for deadline
                ethAmount := shr(176, loaded)
                arguments.offset := add(107, 10) // Skip the 10-byte ethAmount
                arguments.length := sub(calldatasize(), add(107, 10))
            }
            _executeSessionArbitraryWithValueNoReturn(
                signature, nonceBytes, deadlineBytes, msg.data[nonceEnd:nonceEnd + 20], ethAmount, arguments
            );
            assembly ("memory-safe") {
                return(0x00, 0x00)
            }
        } else if (functionSelector == bytes1(0x60)) {
            // executeBatchSessionArbitrary
            IBatchExecution.Call[] calldata calls;
            assembly ("memory-safe") {
                calls.offset := add(87, 0x40) // Updated offset for deadline (no outputContract)
                calls.length := calldataload(add(87, 0x20))
            }
            _executeBatchSessionArbitraryNoReturn(signature, nonceBytes, deadlineBytes, calls);
            assembly ("memory-safe") {
                return(0x00, 0x00)
            }
        }
        // RETURN PATHS (0xX1) - Checked after no-return paths
        else if (functionSelector == bytes1(0x01)) {
            // execute (with return) - handles both with and without value
            address outputContract;
            uint256 ethAmount;
            bytes calldata arguments;
            assembly ("memory-safe") {
                let data := calldataload(nonceEnd)
                outputContract := shr(96, data)
                let loaded := calldataload(add(nonceEnd, 20))
                ethAmount := shr(176, loaded)
                arguments.offset := add(nonceEnd, 30)
                arguments.length := sub(calldatasize(), add(nonceEnd, 30))
            }
            bytes memory result;
            if (ethAmount == 0) {
                result = _executeNoValue(signature, nonceBytes, deadlineBytes, outputContract, arguments);
            } else {
                result = _executeWithValue(signature, nonceBytes, deadlineBytes, outputContract, ethAmount, arguments);
            }
            return result;
        } else if (functionSelector == bytes1(0x11)) {
            // approveThenExecute with return
            address erc20;
            address spender;
            uint256 approveAmount;
            address outputContract;
            uint256 ethAmount;
            assembly ("memory-safe") {
                erc20 := shr(96, calldataload(nonceEnd))
                spender := shr(96, calldataload(add(nonceEnd, 20)))
                approveAmount := calldataload(add(nonceEnd, 40))
                outputContract := shr(96, calldataload(add(nonceEnd, 72)))
                let loaded := calldataload(add(nonceEnd, 92))
                ethAmount := shr(176, loaded) // 10 bytes, right-aligned
            }
            bytes memory result = _approveThenExecuteWithParams(
                signature,
                nonceBytes,
                deadlineBytes,
                erc20,
                spender,
                approveAmount,
                outputContract,
                ethAmount,
                msg.data[nonceEnd + 102:] //arguments
            );
            return result;
        } else if (functionSelector == bytes1(0x21)) {
            // executeBatch with return
            bytes[] memory result = _executeBatch(signature, nonceBytes, deadlineBytes, msg.data[nonceEnd:]);
            return abi.encode(result);
        } else if (functionSelector == bytes1(0x31)) {
            address outputContract;
            uint256 ethAmount;
            bytes calldata arguments;
            assembly ("memory-safe") {
                outputContract := shr(96, calldataload(87)) // Updated offset for deadline
                let w := calldataload(107) // Updated offset for deadline
                ethAmount := shr(176, w) // (32-10)*8
                arguments.offset := add(107, 10) // Skip the 10-byte ethAmount
                arguments.length := sub(calldatasize(), add(107, 10))
            }

            bytes memory result =
                _executeSessionWithValue(signature, nonceBytes, deadlineBytes, outputContract, ethAmount, arguments);
            return result;
        } else if (functionSelector == bytes1(0x41)) {
            // executeBatchSession with return
            address outputContract;
            IBatchExecution.Call[] calldata calls;
            assembly ("memory-safe") {
                outputContract := shr(96, calldataload(87)) // Updated offset for deadline
                calls.offset := add(107, 0x40) // Updated offset for deadline
                calls.length := calldataload(add(107, 0x20))
            }

            bytes[] memory result = _executeBatchSession(signature, nonceBytes, deadlineBytes, outputContract, calls);
            return abi.encode(result);
        } else if (functionSelector == bytes1(0x51)) {
            // executeSessionArbitraryWithValue with return
            address outputContract;
            uint256 ethAmount;
            bytes calldata arguments;
            assembly ("memory-safe") {
                outputContract := shr(96, calldataload(87)) // Updated offset for deadline
                let loaded := calldataload(107) // Updated offset for deadline
                ethAmount := shr(176, loaded)
                arguments.offset := add(107, 10) // Skip the 10-byte ethAmount
                arguments.length := sub(calldatasize(), add(107, 10))
            }
            bytes memory result = _executeSessionArbitraryWithValue(
                signature, nonceBytes, deadlineBytes, outputContract, ethAmount, arguments
            );
            return result;
        } else if (functionSelector == bytes1(0x61)) {
            // executeBatchSessionArbitrary with return
            IBatchExecution.Call[] calldata calls;
            assembly ("memory-safe") {
                calls.offset := add(87, 0x40) // Updated offset for deadline (no outputContract)
                calls.length := calldataload(add(87, 0x20))
            }
            bytes[] memory result = _executeBatchSessionArbitrary(signature, nonceBytes, deadlineBytes, calls);
            return abi.encode(result);
        }

        revert UnsupportedExecutionMode();
    }

    // Internal helpers to centralize common validation logic

    function _validateExecute(bytes32 _hash, bytes calldata _signature, bytes calldata _nonceBytes) internal {
        _requireSelf(_hash, _signature);
        _consumeNonce(_nonceBytes);
    }

    function _validateSession(bytes32 _hash, bytes calldata _signature, bytes calldata _counterBytes) internal view {
        _requireSelf(_hash, _signature);
        _requireCounter(_counterBytes);
    }

    function _requireSelf(bytes32 _hash, bytes calldata _signature) internal view {
        if (!_validateSignature(_hash, _signature)) {
            revert NotSelf();
        }
    }

    function _validateSignature(bytes32 _hash, bytes calldata _signature) internal view virtual returns (bool) {
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
        uint64 prefix = uint64(nonceValue >> 64);
        if (prefix == 0) {
            if (state.nonce != nonceValue) {
                revert InvalidNonce();
            }
            unchecked {
                ++state.nonce;
            }
        } else {
            uint64 noncePart = uint64(nonceValue);
            if (noncePart != state.nonces[prefix]) {
                revert InvalidNonce();
            }
            unchecked {
                ++state.nonces[prefix];
            }
        }
    }

    function _consumeNonce(uint128 _nonce) internal {
        State storage state = _getStateStorage();
        uint64 prefix = uint64(_nonce >> 64);
        if (prefix == 0) {
            if (state.nonce != _nonce) {
                revert InvalidNonce();
            }
            unchecked {
                ++state.nonce;
            }
        } else {
            uint64 noncePart = uint64(_nonce);
            if (noncePart != state.nonces[prefix]) {
                revert InvalidNonce();
            }
            unchecked {
                ++state.nonces[prefix];
            }
        }
    }

    function _requireCounter(bytes calldata _counterBytes) internal view {
        // This call should only happen coming from validateSession, so we can assume the counterBytes are the right length
        if (_getStateStorage().expiredSessionCounters[bytes16(_counterBytes)]) {
            revert InvalidCounter();
        }
    }

    function _requireCounter(uint128 _counter) internal view {
        if (_getStateStorage().expiredSessionCounters[bytes16(_counter)]) {
            revert InvalidCounter();
        }
    }

    /// @notice Returns the EIP-712 domain separator for this contract
    /// @dev Used for signature verification and typed data hashing
    /// @return The EIP-712 domain separator hash
    function getDomainSeparator() external view returns (bytes32) {
        return _domainSeparator();
    }

    function _domainNameAndVersion()
        internal
        pure
        virtual
        override
        returns (string memory name, string memory version)
    {
        name = "TKGasDelegate";
        version = "1";
    }

    /// @notice Executes a transaction and returns the result
    /// @dev Validates signature and nonce before execution. Automatically selects value/no-value path based on _value parameter
    /// @param _to The contract or address to call
    /// @param _value The amount of ETH to send (in wei)
    /// @param _data Encoded data containing signature (65 bytes), nonce (16 bytes), deadline (4 bytes), and arguments
    /// @return The return data from the executed call
    function executeReturns(address _to, uint256 _value, bytes calldata _data) external returns (bytes memory) {
        bytes memory result = _value == 0
            ? _executeNoValue(_data[0:65], _data[65:81], _data[81:85], _to, _data[85:])
            : _executeWithValue(_data[0:65], _data[65:81], _data[81:85], _to, _value, _data[85:]);
        return result;
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

    /// @notice Executes a transaction with all parameters encoded in data, returns result
    /// @dev Parses target address and value from data bytes, then executes
    /// @param data Encoded data: signature(65) + nonce(16) + deadline(4) + to(20) + value(32) + arguments
    /// @return The return data from the executed call
    function executeReturns(bytes calldata data) external returns (bytes memory) {
        address to;
        uint256 value;
        assembly ("memory-safe") {
            // address is 20 bytes immediately after deadline
            to := shr(96, calldataload(add(data.offset, 85)))
            // value is 32 bytes immediately after address
            value := calldataload(add(data.offset, 105))
        }
        bytes memory result = value == 0
            ? _executeNoValue(data[0:65], data[65:81], data[81:85], to, data[137:])
            : _executeWithValue(data[0:65], data[65:81], data[81:85], to, value, data[137:]);
        return result;
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

    /// @notice Approves ERC20 tokens then executes a transaction, returning the result
    /// @dev Parses all parameters from encoded data. Handles USDT-style tokens that require approval reset to 0
    /// @param _data Encoded data: signature(65) + nonce(16) + deadline(4) + erc20(20) + spender(20) + approveAmount(32) + to(20) + value(32) + arguments
    /// @return The return data from the executed call
    function approveThenExecuteReturns(bytes calldata _data) external returns (bytes memory) {
        // Layout: [signature(65)][nonce(16)][deadline(4)][erc20(20)][spender(20)][approveAmount(32)][output(20)][eth(32)][args]
        address erc20;
        address spender;
        uint256 approveAmount;
        address to;
        uint256 value;
        assembly ("memory-safe") {
            erc20 := shr(96, calldataload(add(_data.offset, 85)))
            spender := shr(96, calldataload(add(_data.offset, 105)))
            approveAmount := calldataload(add(_data.offset, 125))
            to := shr(96, calldataload(add(_data.offset, 157)))
            value := calldataload(add(_data.offset, 177))
        }
        return _approveThenExecuteWithParams(
            _data[0:65], _data[65:81], _data[81:85], erc20, spender, approveAmount, to, value, _data[209:]
        );
    }

    /// @notice Approves ERC20 tokens then executes a transaction, returns result
    /// @dev Useful for DEX swaps and similar patterns requiring token approval before execution
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
    ) external returns (bytes memory) {
        bytes memory result = _approveThenExecuteWithParams(
            _data[0:65], _data[65:81], _data[81:85], _erc20, _spender, _approveAmount, _to, _value, _data[85:]
        );
        return result;
    }

    /// @notice Approves ERC20 tokens then executes a transaction, no return
    /// @dev Gas-efficient version when return data is not needed
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
    ) external {
        _approveThenExecuteNoReturnWithParams(
            _data[0:65], _data[65:81], _data[81:85], _erc20, _spender, _approveAmount, _to, _value, _data[85:]
        );
    }

    function _approveThenExecuteWithParams(
        bytes calldata _signature, // 65 bytes
        bytes calldata _nonceBytes, // uint128
        bytes calldata _deadlineBytes, // uint32
        address _erc20,
        address _spender,
        uint256 _approveAmount,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments
    ) internal returns (bytes memory) {
        bytes32 hash;
        assembly ("memory-safe") {
            let deadline := shr(224, calldataload(_deadlineBytes.offset))
            if gt(timestamp(), deadline) {
                let errorPtr := mload(0x40)
                mstore(errorPtr, DEADLINE_EXCEEDED_SELECTOR)
                revert(errorPtr, 0x04)
            } // DeadlineExceeded
            let ptr := mload(0x40)
            mstore(ptr, APPROVE_THEN_EXECUTE_TYPEHASH)
            let nonceValue := shr(128, calldataload(_nonceBytes.offset))
            mstore(add(ptr, 0x20), nonceValue)
            mstore(add(ptr, 0x40), deadline)
            mstore(add(ptr, 0x60), _erc20)
            mstore(add(ptr, 0x80), _spender)
            mstore(add(ptr, 0xa0), _approveAmount)
            mstore(add(ptr, 0xc0), _outputContract)
            mstore(add(ptr, 0xe0), _ethAmount)
            // Compute argsHash in assembly
            let argsPtr := add(ptr, 0x100)
            calldatacopy(argsPtr, _arguments.offset, _arguments.length)
            let argsHash := keccak256(argsPtr, _arguments.length)
            mstore(add(ptr, 0x100), argsHash)
            // total = 0x120 (288) bytes
            hash := keccak256(ptr, 0x120)
            mstore(0x40, add(ptr, 0x120))
        }
        hash = _hashTypedData(hash);

        _validateExecute(hash, _signature, _nonceBytes);

        // Build calldata for approve(spender, amount) and call token
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, shl(224, 0x095ea7b3)) // IERC20.approve selector
            mstore(add(ptr, 0x04), _spender)
            mstore(add(ptr, 0x24), _approveAmount)
            let approveReturnPtr := mload(0x40)
            let success := call(gas(), _erc20, 0, ptr, 0x44, approveReturnPtr, 0x20)
            switch success
            case 0 {
                // attempt a special case for usdt on eth mainnet usually requires resetting approval to 0 then setting it again
                //mstore(ptr, shl(224, 0x095ea7b3)) // IERC20.approve selector
                //mstore(add(ptr, 0x04), _spender)
                mstore(add(ptr, 0x24), 0) // zero out the approve amount
                if iszero(call(gas(), _erc20, 0, ptr, 0x44, 0, 0)) {
                    // we don't care about the return value here
                    mstore(0x00, APPROVAL_TO_0_FAILED_SELECTOR)
                    revert(0x00, 0x04)
                }
                //mstore(ptr, shl(224, 0x095ea7b3)) // IERC20.approve selector
                //mstore(add(ptr, 0x04), _spender)
                mstore(add(ptr, 0x24), _approveAmount) // rewrite the approve amount
                if iszero(call(gas(), _erc20, 0, ptr, 0x44, approveReturnPtr, 0x20)) {
                    mstore(0x00, APPROVAL_FAILED_SELECTOR)
                    revert(0x00, 0x04)
                }
            }
            if iszero(or(iszero(returndatasize()), mload(approveReturnPtr))) {
                mstore(0x00, APPROVAL_RETURN_FALSE_SELECTOR)
                revert(0x00, 0x04)
            }
            mstore(0x40, add(ptr, 0x64))
        }

        (bool success, bytes memory result) =
            _ethAmount == 0 ? _outputContract.call(_arguments) : _outputContract.call{value: _ethAmount}(_arguments);
        if (success) {
            return result;
        }
        revert ExecutionFailed();
    }

    function _approveThenExecuteNoReturnWithParams(
        bytes calldata _signature, // 65 bytes
        bytes calldata _nonceBytes, // uint128
        bytes calldata _deadlineBytes, // uint32
        address _erc20,
        address _spender,
        uint256 _approveAmount,
        address _outputContract,
        uint256 _ethAmount,
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
            mstore(ptr, APPROVE_THEN_EXECUTE_TYPEHASH)
            let nonceValue := shr(128, calldataload(_nonceBytes.offset))
            mstore(add(ptr, 0x20), nonceValue)
            mstore(add(ptr, 0x40), deadline)
            mstore(add(ptr, 0x60), _erc20)
            mstore(add(ptr, 0x80), _spender)
            mstore(add(ptr, 0xa0), _approveAmount)
            mstore(add(ptr, 0xc0), _outputContract)
            mstore(add(ptr, 0xe0), _ethAmount)
            // Compute argsHash in assembly
            let argsPtr := add(ptr, 0x100)
            calldatacopy(argsPtr, _arguments.offset, _arguments.length)
            let argsHash := keccak256(argsPtr, _arguments.length)
            mstore(add(ptr, 0x100), argsHash)
            // total = 0x120 (288) bytes
            hash := keccak256(ptr, 0x120)
            mstore(0x40, add(ptr, 0x120))
        }
        hash = _hashTypedData(hash);

        _validateExecute(hash, _signature, _nonceBytes);

        // Build calldata for approve(spender, amount) and call token
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, shl(224, 0x095ea7b3)) // IERC20.approve selector
            mstore(add(ptr, 0x04), _spender)
            mstore(add(ptr, 0x24), _approveAmount)
            let approveReturnPtr := mload(0x40)
            let success := call(gas(), _erc20, 0, ptr, 0x44, approveReturnPtr, 0x20)
            switch success
            case 0 {
                // attempt a special case for usdt on eth mainnet usually requires resetting approval to 0 then setting it again
                //mstore(ptr, shl(224, 0x095ea7b3)) // IERC20.approve selector
                //mstore(add(ptr, 0x04), _spender)
                mstore(add(ptr, 0x24), 0)
                if iszero(call(gas(), _erc20, 0, ptr, 0x44, 0, 0)) {
                    mstore(0x00, APPROVAL_TO_0_FAILED_SELECTOR)
                    revert(0x00, 0x04)
                }
                //mstore(ptr, shl(224, 0x095ea7b3)) // IERC20.approve selector
                //mstore(add(ptr, 0x04), _spender)
                mstore(add(ptr, 0x24), _approveAmount)
                if iszero(call(gas(), _erc20, 0, ptr, 0x44, approveReturnPtr, 0x20)) {
                    mstore(0x00, APPROVAL_FAILED_SELECTOR)
                    revert(0x00, 0x04)
                }
            }
            if iszero(or(iszero(returndatasize()), mload(approveReturnPtr))) {
                mstore(0x00, APPROVAL_RETURN_FALSE_SELECTOR)
                revert(0x00, 0x04)
            }
            mstore(0x40, add(ptr, 0x64))
        }

        // Execute the call without returning the result
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            calldatacopy(ptr, _arguments.offset, _arguments.length)
            if iszero(call(gas(), _outputContract, _ethAmount, ptr, _arguments.length, 0, 0)) { revert(0, 0) }
            // No need to restore free memory pointer - execution ends immediately
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

    function _executeNoValue(
        bytes calldata _signature,
        bytes calldata _nonceBytes,
        bytes calldata _deadlineBytes,
        address _outputContract,
        bytes calldata _arguments
    ) internal returns (bytes memory) {
        bytes32 hash;
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
            mstore(add(ptr, 0x80), 0) // ethAmount = 0
            // Compute argsHash in assembly
            let argsPtr := add(ptr, 0xa0)
            calldatacopy(argsPtr, _arguments.offset, _arguments.length)
            let argsHash := keccak256(argsPtr, _arguments.length)
            mstore(add(ptr, 0xa0), argsHash)
            hash := keccak256(ptr, 0xc0)
            mstore(0x40, add(ptr, 0xc0))
        }
        hash = _hashTypedData(hash);

        _validateExecute(hash, _signature, _nonceBytes);
        (bool success, bytes memory result) = _outputContract.call(_arguments);
        if (success) {
            return result;
        }
        revert ExecutionFailed();
    }

    function _executeWithValue(
        bytes calldata _signature,
        bytes calldata _nonceBytes,
        bytes calldata _deadlineBytes,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments
    ) internal returns (bytes memory) {
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
            // Compute argsHash in assembly
            let argsPtr := add(ptr, 0xa0)
            calldatacopy(argsPtr, _arguments.offset, _arguments.length)
            let argsHash := keccak256(argsPtr, _arguments.length)
            mstore(add(ptr, 0xa0), argsHash)
            hash := keccak256(ptr, 0xc0)
            mstore(0x40, add(ptr, 0xc0))
        }
        hash = _hashTypedData(hash);

        _validateExecute(hash, _signature, _nonceBytes);
        (bool success, bytes memory result) = _outputContract.call{value: _ethAmount}(_arguments);
        if (success) {
            return result;
        }
        revert ExecutionFailed();
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

    /// @notice Burns a specific nonce to invalidate it
    /// @dev Prevents replay of transactions signed with this nonce. Requires signature authorization
    /// @param _signature The signature authorizing the nonce burn (65 bytes)
    /// @param _nonce The nonce value to burn (will be consumed, blocking its use)
    function burnNonce(bytes calldata _signature, uint128 _nonce) external {
        bytes32 hash;
        assembly ("memory-safe") {
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

    /// @notice Burns the current nonce without signature (must be called by self)
    /// @dev Can only be called by the contract itself. Increments the nonce to invalidate the current value
    function burnNonce() external {
        if (msg.sender != address(this) || msg.sender != tx.origin) {
            revert NotSelf();
        }
        unchecked {
            ++_getStateStorage().nonce; // assume the 0 prefix
        }
    }

    function burnNonce(uint64 _prefix) external {
        if (msg.sender != address(this) || msg.sender != tx.origin) {
            revert NotSelf();
        }
        if (_prefix == 0) {
            unchecked {
                ++_getStateStorage().nonce;
            }
        } else {
            unchecked {
                ++_getStateStorage().nonces[_prefix];
            }
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
    ) internal returns (bytes memory) {
        // Check if deadline has passed using calldata
        address sender = msg.sender;
        bytes32 hash;
        assembly ("memory-safe") {
            let deadline := shr(224, calldataload(_deadlineBytes.offset))
            if gt(timestamp(), deadline) {
                let errorPtr := mload(0x40)
                mstore(errorPtr, DEADLINE_EXCEEDED_SELECTOR)
                revert(errorPtr, 0x04)
            } // DeadlineExceeded
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, SESSION_EXECUTION_TYPEHASH)
            let counterValue := shr(128, calldataload(_counterBytes.offset))
            mstore(add(ptr, 0x20), counterValue)
            mstore(add(ptr, 0x40), deadline)
            mstore(add(ptr, 0x60), sender)
            mstore(add(ptr, 0x80), _outputContract)
            hash := keccak256(ptr, 0xa0)
            mstore(0x40, add(ptr, 0xa0))
        }
        hash = _hashTypedData(hash);

        _validateSession(hash, _signature, _counterBytes);

        (bool success, bytes memory result) = _outputContract.call{value: _ethAmount}(_arguments);

        if (success) {
            return result;
        }
        revert ExecutionFailed();
    }

    function _executeSessionWithValueNoReturn(
        bytes calldata _signature,
        bytes calldata _counterBytes,
        bytes calldata _deadlineBytes,
        bytes calldata _outputContractBytes,
        uint256 _ethAmount,
        bytes calldata _arguments
    ) internal {
        address sender = msg.sender;
        bytes32 hash;
        assembly ("memory-safe") {
            let deadline := shr(224, calldataload(_deadlineBytes.offset))
            if gt(timestamp(), deadline) {
                // Use precomputed selector and revert with 4-byte custom error
                mstore(0x00, DEADLINE_EXCEEDED_SELECTOR)
                revert(0x00, 0x04)
            }
            let ptr := mload(0x40)
            mstore(ptr, SESSION_EXECUTION_TYPEHASH)
            let counterValue := shr(128, calldataload(_counterBytes.offset))
            mstore(add(ptr, 0x20), counterValue)
            mstore(add(ptr, 0x40), deadline)
            mstore(add(ptr, 0x60), sender)
            let raw := calldataload(_outputContractBytes.offset)
            mstore(add(ptr, 0x80), shr(96, raw))
            hash := keccak256(ptr, 0xa0)
            mstore(0x40, add(ptr, 0xa0))
        }
        hash = _hashTypedData(hash);

        _validateSession(hash, _signature, _counterBytes);
        assembly ("memory-safe") {
            let outputContract := shr(96, calldataload(_outputContractBytes.offset))
            let ptr := mload(0x40)
            calldatacopy(ptr, _arguments.offset, _arguments.length)
            if iszero(call(gas(), outputContract, _ethAmount, ptr, _arguments.length, 0, 0)) { revert(0, 0) }
            mstore(0x40, add(ptr, _arguments.length))
        }
    }

    function _executeSessionWithValueNoReturn(
        bytes calldata _signature,
        bytes calldata _counterBytes,
        bytes calldata _deadlineBytes,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments
    ) internal {
        address sender = msg.sender;
        bytes32 hash;
        assembly ("memory-safe") {
            let deadline := shr(224, calldataload(_deadlineBytes.offset))
            if gt(timestamp(), deadline) {
                // Use precomputed selector and revert with 4-byte custom error
                mstore(0x00, DEADLINE_EXCEEDED_SELECTOR)
                revert(0x00, 0x04)
            }
            let ptr := mload(0x40)
            mstore(ptr, SESSION_EXECUTION_TYPEHASH)
            let counterValue := shr(128, calldataload(_counterBytes.offset))
            mstore(add(ptr, 0x20), counterValue)
            mstore(add(ptr, 0x40), deadline)
            mstore(add(ptr, 0x60), sender)
            mstore(add(ptr, 0x80), _outputContract)
            hash := keccak256(ptr, 0xa0)
            mstore(0x40, add(ptr, 0xa0))
        }
        hash = _hashTypedData(hash);

        _validateSession(hash, _signature, _counterBytes);
        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, _arguments.offset, _arguments.length)
            if iszero(call(gas(), _outputContract, _ethAmount, ptr, _arguments.length, 0, 0)) { revert(0, 0) }
            // No need to restore free memory pointer - execution ends immediately
        }
    }

    function _executeBatchSession(
        bytes calldata _signature,
        bytes calldata _counterBytes,
        bytes calldata _deadlineBytes,
        address _outputContract,
        IBatchExecution.Call[] calldata _calls
    ) internal returns (bytes[] memory) {
        // Check if deadline has passed using calldata
        uint256 length = _calls.length;

        if (length > MAX_BATCH_SIZE || length == 0) {
            revert BatchSizeInvalid();
        }

        bytes32 hash;
        assembly ("memory-safe") {
            let deadline := shr(224, calldataload(_deadlineBytes.offset))
            if gt(timestamp(), deadline) {
                let errorPtr := mload(0x40)
                mstore(errorPtr, DEADLINE_EXCEEDED_SELECTOR)
                revert(errorPtr, 0x04)
            } // DeadlineExceeded
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, SESSION_EXECUTION_TYPEHASH)
            // Copy counter bytes directly to memory
            let counterValue := shr(128, calldataload(_counterBytes.offset))
            mstore(add(ptr, 0x20), counterValue)
            mstore(add(ptr, 0x40), deadline)
            mstore(add(ptr, 0x60), caller())
            mstore(add(ptr, 0x80), _outputContract)
            hash := keccak256(ptr, 0xa0)
            mstore(0x40, add(ptr, 0xa0))
        }
        hash = _hashTypedData(hash);
        _validateSession(hash, _signature, _counterBytes);

        // Execute the session transaction
        bytes[] memory results = new bytes[](length);

        // Cache array access to avoid repeated calldata reads
        for (uint256 i = 0; i < length;) {
            IBatchExecution.Call calldata execution = _calls[i];
            uint256 ethAmount = execution.value;
            address outputContract = execution.to;
            // do not cache execution.data - leave it as calldata
            if (outputContract != _outputContract) {
                revert InvalidToContract();
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

        return results;
    }

    function _executeBatchSessionNoReturn(
        bytes calldata _signature,
        bytes calldata _counterBytes,
        bytes calldata _deadlineBytes,
        bytes calldata _outputContractBytes,
        IBatchExecution.Call[] calldata _calls
    ) internal {
        uint256 length = _calls.length;
        if (length > MAX_BATCH_SIZE || length == 0) {
            revert BatchSizeInvalid();
        }
        bytes32 hash;
        assembly ("memory-safe") {
            let deadline := shr(224, calldataload(_deadlineBytes.offset))
            if gt(timestamp(), deadline) {
                let errorPtr := mload(0x40)
                mstore(errorPtr, DEADLINE_EXCEEDED_SELECTOR)
                revert(errorPtr, 0x04)
            } // DeadlineExceeded
            let ptr := mload(0x40)
            mstore(ptr, SESSION_EXECUTION_TYPEHASH)
            let counterValue := shr(128, calldataload(_counterBytes.offset))
            mstore(add(ptr, 0x20), counterValue)
            mstore(add(ptr, 0x40), deadline)
            mstore(add(ptr, 0x60), caller())
            let raw := calldataload(_outputContractBytes.offset)
            mstore(add(ptr, 0x80), shr(96, raw))
            hash := keccak256(ptr, 0xa0)
            mstore(0x40, add(ptr, 0xa0))
        }
        hash = _hashTypedData(hash);
        _validateSession(hash, _signature, _counterBytes);

        for (uint256 i = 0; i < length;) {
            IBatchExecution.Call calldata execution = _calls[i];
            uint256 ethAmount = execution.value;
            address outputContract = execution.to;
            if (bytes20(outputContract) != bytes20(_outputContractBytes)) {
                revert InvalidToContract();
            }
            bytes calldata _callData = execution.data;
            assembly ("memory-safe") {
                let ptr := mload(0x40)
                calldatacopy(ptr, _callData.offset, _callData.length)
                if iszero(call(gas(), outputContract, ethAmount, ptr, _callData.length, 0, 0)) { revert(0, 0) }
                mstore(0x40, add(ptr, _callData.length))
            }
            unchecked {
                ++i;
            }
        }
    }

    function _executeBatchSessionNoReturn(
        bytes calldata _signature,
        bytes calldata _counterBytes,
        bytes calldata _deadlineBytes,
        address _outputContract,
        IBatchExecution.Call[] calldata _calls
    ) internal {
        if (_calls.length > MAX_BATCH_SIZE || _calls.length == 0) {
            revert BatchSizeInvalid();
        }

        bytes32 hash;
        assembly ("memory-safe") {
            let deadline := shr(224, calldataload(_deadlineBytes.offset))
            if gt(timestamp(), deadline) {
                let errorPtr := mload(0x40)
                mstore(errorPtr, DEADLINE_EXCEEDED_SELECTOR)
                revert(errorPtr, 0x04)
            } // DeadlineExceeded
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, SESSION_EXECUTION_TYPEHASH)
            // Copy counter bytes directly to memory
            let counterValue := shr(128, calldataload(_counterBytes.offset))
            mstore(add(ptr, 0x20), counterValue)
            mstore(add(ptr, 0x40), deadline)
            mstore(add(ptr, 0x60), caller())
            mstore(add(ptr, 0x80), _outputContract)
            hash := keccak256(ptr, 0xa0)
            mstore(0x40, add(ptr, 0xa0))
        }
        hash = _hashTypedData(hash);
        _validateSession(hash, _signature, _counterBytes);

        // Execute the session transaction
        uint256 length = _calls.length;

        // Cache array access to avoid repeated calldata reads
        for (uint256 i = 0; i < length;) {
            IBatchExecution.Call calldata execution = _calls[i];
            uint256 ethAmount = execution.value;
            address outputContract = execution.to;
            bytes calldata _callData = execution.data;

            // Validate that all calls are to the same output contract
            if (outputContract != _outputContract) {
                revert InvalidToContract();
            }

            assembly ("memory-safe") {
                let ptr := mload(0x40)
                calldatacopy(ptr, _callData.offset, _callData.length)
                if iszero(call(gas(), outputContract, ethAmount, ptr, _callData.length, 0, 0)) { revert(0, 0) }
                mstore(0x40, add(ptr, _callData.length))
            }
            unchecked {
                ++i;
            }
        }
    }

    function _executeSessionArbitraryWithValue(
        bytes calldata _signature,
        bytes calldata _counterBytes,
        bytes calldata _deadlineBytes,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments
    ) internal returns (bytes memory) {
        // Check if deadline has passed using calldata
        bytes32 hash;
        assembly ("memory-safe") {
            let deadline := shr(224, calldataload(_deadlineBytes.offset))
            if gt(timestamp(), deadline) {
                let errorPtr := mload(0x40)
                mstore(errorPtr, DEADLINE_EXCEEDED_SELECTOR)
                revert(errorPtr, 0x04)
            } // DeadlineExceeded
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, ARBITRARY_SESSION_EXECUTION_TYPEHASH)
            // Copy counter bytes directly to memory
            let counterValue := shr(128, calldataload(_counterBytes.offset))
            mstore(add(ptr, 0x20), counterValue)
            // Store previously loaded deadline directly to memory
            mstore(add(ptr, 0x40), deadline)
            mstore(add(ptr, 0x60), caller())
            hash := keccak256(ptr, 0x80)
            mstore(0x40, add(ptr, 0x80))
        }
        hash = _hashTypedData(hash);
        _validateSession(hash, _signature, _counterBytes);
        // Execute the session transaction
        (bool success, bytes memory result) = _outputContract.call{value: _ethAmount}(_arguments);
        if (success) {
            return result;
        }
        revert ExecutionFailed();
    }

    function _executeSessionArbitraryWithValueNoReturn(
        bytes calldata _signature,
        bytes calldata _counterBytes,
        bytes calldata _deadlineBytes,
        bytes calldata _outputContractBytes,
        uint256 _ethAmount,
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
            mstore(ptr, ARBITRARY_SESSION_EXECUTION_TYPEHASH)
            let counterValue := shr(128, calldataload(_counterBytes.offset))
            mstore(add(ptr, 0x20), counterValue)
            mstore(add(ptr, 0x40), deadline)
            mstore(add(ptr, 0x60), caller())
            hash := keccak256(ptr, 0x80)
            mstore(0x40, add(ptr, 0x80))
        }
        hash = _hashTypedData(hash);
        _validateSession(hash, _signature, _counterBytes);
        assembly {
            let outputContract := shr(96, calldataload(_outputContractBytes.offset))
            let ptr := mload(0x40)
            calldatacopy(ptr, _arguments.offset, _arguments.length)
            if iszero(call(gas(), outputContract, _ethAmount, ptr, _arguments.length, 0, 0)) { revert(0, 0) }
            //no need to restore free memory pointer - execution ends immediately
        }
    }

    function _executeSessionArbitraryWithValueNoReturn(
        bytes calldata _signature,
        bytes calldata _counterBytes,
        bytes calldata _deadlineBytes,
        address _outputContract,
        uint256 _ethAmount,
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
            mstore(ptr, ARBITRARY_SESSION_EXECUTION_TYPEHASH)
            let counterValue := shr(128, calldataload(_counterBytes.offset))
            mstore(add(ptr, 0x20), counterValue)
            mstore(add(ptr, 0x40), deadline)
            mstore(add(ptr, 0x60), caller())
            hash := keccak256(ptr, 0x80)
            mstore(0x40, add(ptr, 0x80))
        }
        hash = _hashTypedData(hash);
        _validateSession(hash, _signature, _counterBytes);
        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, _arguments.offset, _arguments.length)
            if iszero(call(gas(), _outputContract, _ethAmount, ptr, _arguments.length, 0, 0)) { revert(0, 0) }
            // No need to restore free memory pointer - execution ends immediately
        }
    }

    function _executeBatchSessionArbitrary(
        bytes calldata _signature,
        bytes calldata _counterBytes,
        bytes calldata _deadlineBytes, // Changed from uint128
        IBatchExecution.Call[] calldata _calls
    ) internal returns (bytes[] memory) {
        uint256 length = _calls.length;
        if (length > MAX_BATCH_SIZE || length == 0) {
            revert BatchSizeInvalid();
        }
        bytes32 hash;
        assembly ("memory-safe") {
            let deadline := shr(224, calldataload(_deadlineBytes.offset))
            if gt(timestamp(), deadline) {
                let errorPtr := mload(0x40)
                mstore(errorPtr, DEADLINE_EXCEEDED_SELECTOR)
                revert(errorPtr, 0x04)
            } // DeadlineExceeded

            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, ARBITRARY_SESSION_EXECUTION_TYPEHASH)
            // Copy counter bytes directly to memory
            let counterValue := shr(128, calldataload(_counterBytes.offset))
            mstore(add(ptr, 0x20), counterValue)
            // Store previously loaded deadline directly to memory
            mstore(add(ptr, 0x40), deadline)
            mstore(add(ptr, 0x60), caller())
            hash := keccak256(ptr, 0x80)
            mstore(0x40, add(ptr, 0x80))
        }
        hash = _hashTypedData(hash);
        _validateSession(hash, _signature, _counterBytes);
        // Execute the session transaction
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

        return results;
    }

    function _executeBatchSessionArbitraryNoReturn(
        bytes calldata _signature,
        bytes calldata _counterBytes,
        bytes calldata _deadlineBytes,
        IBatchExecution.Call[] calldata _calls
    ) internal {
        uint256 length = _calls.length;
        if (length > MAX_BATCH_SIZE || length == 0) revert BatchSizeInvalid();
        bytes32 hash;
        assembly ("memory-safe") {
            let deadline := shr(224, calldataload(_deadlineBytes.offset))
            if gt(timestamp(), deadline) {
                // Use precomputed selector and revert with 4-byte custom error
                mstore(0x00, DEADLINE_EXCEEDED_SELECTOR)
                revert(0x00, 0x04)
            }

            let ptr := mload(0x40)
            mstore(ptr, ARBITRARY_SESSION_EXECUTION_TYPEHASH)
            let counterValue := shr(128, calldataload(_counterBytes.offset))
            mstore(add(ptr, 0x20), counterValue)
            mstore(add(ptr, 0x40), deadline)
            mstore(add(ptr, 0x60), caller())
            hash := keccak256(ptr, 0x80)
            mstore(0x40, add(ptr, 0x80))
        }
        hash = _hashTypedData(hash);
        _validateSession(hash, _signature, _counterBytes);

        for (uint256 i = 0; i < length;) {
            IBatchExecution.Call calldata execution = _calls[i];
            uint256 ethAmount = execution.value;
            address outputContract = execution.to;
            bytes calldata _callData = execution.data;
            assembly ("memory-safe") {
                let ptr := mload(0x40)
                calldatacopy(ptr, _callData.offset, _callData.length)
                if iszero(call(gas(), outputContract, ethAmount, ptr, _callData.length, 0, 0)) { revert(0, 0) }
                mstore(0x40, add(ptr, _callData.length))
            }
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Burns a session counter to revoke all sessions using that counter
    /// @dev Marks the counter as expired, preventing future session executions with this counter
    /// @param _signature The signature authorizing the counter burn (65 bytes)
    /// @param _counter The session counter value to burn
    function burnSessionCounter(bytes calldata _signature, uint128 _counter) external {
        bytes32 hash;
        assembly ("memory-safe") {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, BURN_SESSION_COUNTER_TYPEHASH)
            mstore(add(ptr, 0x20), _counter)
            hash := keccak256(ptr, 0x40)
            mstore(0x40, add(ptr, 0x40)) // Update free memory pointer
        }
        hash = _hashTypedData(hash);

        _requireCounter(_counter);
        if (ECDSA.recoverCalldata(hash, _signature) != address(this)) {
            revert NotSelf();
        }
        _getStateStorage().expiredSessionCounters[bytes16(_counter)] = true;
    }

    /// @notice Burns a session counter without signature (must be called by self)
    /// @dev Can only be called by the contract itself to revoke session permissions
    /// @param _counter The session counter value to burn
    function burnSessionCounter(uint128 _counter) external {
        if (msg.sender != address(this) || msg.sender != tx.origin) {
            revert NotSelf();
        }
        _getStateStorage().expiredSessionCounters[bytes16(_counter)] = true; // does not need to check if the counter is already expired
    }

    /// @notice Executes a session transaction and returns the result
    /// @dev Sessions allow authorized senders to execute transactions without full EOA signature. Uses counter instead of nonce
    /// @param data Encoded data: signature(65) + counter(16) + deadline(4) + output(20) + ethAmount(32) + arguments
    /// @return The return data from the executed call
    function executeSessionReturns(bytes calldata data) external returns (bytes memory) {
        // Layout: [signature(65)][counter(16)][deadline(4)][output(20)][ethAmount(32)][args]
        address output;
        uint256 ethAmount;
        assembly ("memory-safe") {
            output := shr(96, calldataload(add(data.offset, 85)))
            ethAmount := calldataload(add(data.offset, 105))
        }
        bytes memory result =
            _executeSessionWithValue(data[0:65], data[65:81], data[81:85], output, ethAmount, data[137:]);
        return result;
    }

    /// @notice Executes a session transaction to a specific contract, returns result
    /// @dev Session must be authorized for the specific _to address
    /// @param _to The contract address to call (must match session authorization)
    /// @param _value The amount of ETH to send (in wei)
    /// @param _data Encoded signature, counter, deadline, and call arguments
    /// @return The return data from the executed call
    function executeSessionReturns(address _to, uint256 _value, bytes calldata _data) external returns (bytes memory) {
        bytes memory result = _executeSessionWithValue(_data[0:65], _data[65:81], _data[81:85], _to, _value, _data[85:]);
        return result;
    }

    /// @notice Executes a session transaction without returning data (gas-efficient)
    /// @dev Session must be authorized for the specific _to address
    /// @param _to The contract address to call
    /// @param _value The amount of ETH to send (in wei)
    /// @param _data Encoded signature, counter, deadline, and call arguments
    function executeSession(address _to, uint256 _value, bytes calldata _data) external {
        _executeSessionWithValueNoReturn(_data[0:65], _data[65:81], _data[81:85], _to, _value, _data[85:]);
    }

    function executeBatchSessionReturns(bytes calldata _data) external returns (bytes[] memory) {
        // Layout: [signature(65)][counter(16)][deadline(4)][output(20)][abi.encode(IBatchExecution.Call[])]
        IBatchExecution.Call[] calldata calls;
        address output;
        assembly ("memory-safe") {
            output := shr(96, calldataload(add(_data.offset, 85)))

            // ABI: at offset 105, we have the head for the dynamic array: [offset=0x20][length][elements]
            let arrayStart := add(_data.offset, 105)
            let offsetPointer := calldataload(arrayStart)
            // If offset pointer is not 0x20, the length is not at the expected position
            if iszero(eq(offsetPointer, 0x20)) {
                let errorPtr := mload(0x40)
                mstore(errorPtr, INVALID_OFFSET_SELECTOR)
                revert(errorPtr, 0x04)
            }
            // With offset pointer = 0x20, length is at arrayStart + 0x20, data starts at arrayStart + 0x40
            let lengthPos := add(arrayStart, 0x20)
            calls.offset := add(arrayStart, 0x40)
            calls.length := calldataload(lengthPos)
        }
        bytes[] memory results = _executeBatchSession(_data[0:65], _data[65:81], _data[81:85], output, calls);
        return results;
    }

    function executeBatchSessionReturns(IBatchExecution.Call[] calldata _calls, bytes calldata _data)
        external
        returns (bytes[] memory)
    {
        address output;
        assembly ("memory-safe") {
            output := shr(96, calldataload(add(_data.offset, 85)))
        }
        bytes[] memory results = _executeBatchSession(_data[0:65], _data[65:81], _data[81:85], output, _calls);
        return results;
    }

    function executeBatchSession(IBatchExecution.Call[] calldata _calls, bytes calldata _data) external {
        address output;
        assembly ("memory-safe") {
            output := shr(96, calldataload(add(_data.offset, 85)))
        }
        _executeBatchSessionNoReturn(_data[0:65], _data[65:81], _data[81:85], output, _calls);
    }

    function executeSessionArbitraryReturns(bytes calldata data) external returns (bytes memory) {
        // does not limit output contract
        // Layout: [signature(65)][counter(16)][deadline(4)][output(20)][ethAmount(32)][args]
        address output;
        uint256 ethAmount;
        assembly ("memory-safe") {
            output := shr(96, calldataload(add(data.offset, 85)))
            ethAmount := calldataload(add(data.offset, 105))
        }
        bytes memory result =
            _executeSessionArbitraryWithValue(data[0:65], data[65:81], data[81:85], output, ethAmount, data[137:]);
        return result;
    }

    function executeSessionArbitraryReturns(address _to, uint256 _value, bytes calldata _data)
        external
        returns (bytes memory)
    {
        bytes memory result =
            _executeSessionArbitraryWithValue(_data[0:65], _data[65:81], _data[81:85], _to, _value, _data[85:]);
        return result;
    }

    function executeSessionArbitrary(address _to, uint256 _value, bytes calldata _data) external {
        _executeSessionArbitraryWithValueNoReturn(_data[0:65], _data[65:81], _data[81:85], _to, _value, _data[85:]);
    }

    function executeBatchSessionArbitraryReturns(bytes calldata _data) external returns (bytes[] memory) {
        // Layout: [signature(65)][counter(16)][deadline(4)][abi.encode(IBatchExecution.Call[])]
        IBatchExecution.Call[] calldata calls;
        assembly ("memory-safe") {
            // ABI: at offset 85, we have the head for the dynamic array: [offset=0x20][length][elements]
            let arrayStart := add(_data.offset, 85)
            let offsetPointer := calldataload(arrayStart)
            // If offset pointer is not 0x20, the length is not at the expected position
            if iszero(eq(offsetPointer, 0x20)) {
                let errorPtr := mload(0x40)
                mstore(errorPtr, INVALID_OFFSET_SELECTOR)
                revert(errorPtr, 0x04)
            }
            // With offset pointer = 0x20, length is at arrayStart + 0x20, data starts at arrayStart + 0x40
            let lengthPos := add(arrayStart, 0x20)
            calls.offset := add(arrayStart, 0x40)
            calls.length := calldataload(lengthPos)
        }
        // For arbitrary batch, sender is implicitly msg.sender in typehash, keep as paymaster (msg.sender)
        bytes[] memory results = _executeBatchSessionArbitrary(_data[0:65], _data[65:81], _data[81:85], calls);
        return results;
    }

    function executeBatchSessionArbitraryReturns(IBatchExecution.Call[] calldata _calls, bytes calldata _data)
        external
        returns (bytes[] memory)
    {
        bytes[] memory results = _executeBatchSessionArbitrary(_data[0:65], _data[65:81], _data[81:85], _calls);
        return results;
    }

    function executeBatchSessionArbitrary(IBatchExecution.Call[] calldata _calls, bytes calldata _data) external {
        _executeBatchSessionArbitraryNoReturn(_data[0:65], _data[65:81], _data[81:85], _calls);
    }

    function executeBatchReturns(bytes calldata data) external returns (bytes[] memory) {
        // Layout: [signature(65)][nonce(16)][deadline(4)][abi.encode(IBatchExecution.Call[])]
        bytes[] memory results = _executeBatch(data[0:65], data[65:81], data[81:85], data[85:]);
        return results;
    }

    function executeBatchReturns(IBatchExecution.Call[] calldata _calls, bytes calldata _data)
        external
        returns (bytes[] memory)
    {
        bytes[] memory results = _executeBatchWithCalls(_data[0:65], _data[65:81], _data[81:85], _calls);
        return results;
    }

    function executeBatch(IBatchExecution.Call[] calldata _calls, bytes calldata _data) external {
        _executeBatchWithCallsNoReturn(_data[0:65], _data[65:81], _data[81:85], _calls);
    }

    function approveThenExecute(bytes calldata data) external {
        // Layout: [signature(65)][nonce(16)][deadline(4)][erc20(20)][spender(20)][approveAmount(32)][output(20)][eth(32)][args]
        address erc20;
        address spender;
        uint256 approveAmount;
        address to;
        uint256 value;
        assembly ("memory-safe") {
            erc20 := shr(96, calldataload(add(data.offset, 85)))
            spender := shr(96, calldataload(add(data.offset, 105)))
            approveAmount := calldataload(add(data.offset, 125))
            to := shr(96, calldataload(add(data.offset, 157)))
            value := calldataload(add(data.offset, 177))
        }
        _approveThenExecuteNoReturnWithParams(
            data[0:65], data[65:81], data[81:85], erc20, spender, approveAmount, to, value, data[209:]
        );
    }

    function executeBatch(bytes calldata data) external {
        _executeBatchNoReturn(data[0:65], data[65:81], data[81:85], data[85:]);
    }

    function executeBatchSession(bytes calldata _data) external {
        IBatchExecution.Call[] calldata calls;
        assembly ("memory-safe") {
            // ABI: at offset 105, we have the head for the dynamic array: [offset=0x20][length][elements]
            let arrayStart := add(_data.offset, 105)
            let offsetPointer := calldataload(arrayStart)
            // If offset pointer is not 0x20, the length is not at the expected position
            if iszero(eq(offsetPointer, 0x20)) {
                let errorPtr := mload(0x40)
                mstore(errorPtr, INVALID_OFFSET_SELECTOR)
                revert(errorPtr, 0x04)
            }
            // With offset pointer = 0x20, length is at arrayStart + 0x20, data starts at arrayStart + 0x40
            let lengthPos := add(arrayStart, 0x20)
            calls.offset := add(arrayStart, 0x40)
            calls.length := calldataload(lengthPos)
        }
        _executeBatchSessionNoReturn(_data[0:65], _data[65:81], _data[81:85], _data[85:105], calls);
    }

    function executeBatchSessionArbitrary(bytes calldata _data) external {
        IBatchExecution.Call[] calldata calls;
        assembly ("memory-safe") {
            // ABI: at offset 85, we have the head for the dynamic array: [offset=0x20][length][elements]
            let arrayStart := add(_data.offset, 85)
            let offsetPointer := calldataload(arrayStart)
            // If offset pointer is not 0x20, the length is not at the expected position
            if iszero(eq(offsetPointer, 0x20)) {
                let errorPtr := mload(0x40)
                mstore(errorPtr, INVALID_OFFSET_SELECTOR)
                revert(errorPtr, 0x04)
            }
            // With offset pointer = 0x20, length is at arrayStart + 0x20, data starts at arrayStart + 0x40
            let lengthPos := add(arrayStart, 0x20)
            calls.offset := add(arrayStart, 0x40)
            calls.length := calldataload(lengthPos)
        }
        _executeBatchSessionArbitraryNoReturn(_data[0:65], _data[65:81], _data[81:85], calls);
    }

    function executeSession(bytes calldata data) external {
        // Parse data to extract parameters and call appropriate internal function
        address to;
        uint256 value;
        assembly ("memory-safe") {
            to := shr(96, calldataload(add(data.offset, 85)))
            value := calldataload(add(data.offset, 105))
        }
        _executeSessionWithValueNoReturn(data[0:65], data[65:81], data[81:85], to, value, data[137:]);
    }

    function executeSessionArbitrary(bytes calldata data) external {
        // Parse data to extract parameters and call appropriate internal function
        address to;
        uint256 value;
        assembly ("memory-safe") {
            to := shr(96, calldataload(add(data.offset, 85)))
            value := calldataload(add(data.offset, 105))
        }
        _executeSessionArbitraryWithValueNoReturn(data[0:65], data[65:81], data[81:85], to, value, data[137:]);
    }

    function _executeBatchWithCalls(
        bytes calldata _signature,
        bytes calldata _nonceBytes,
        bytes calldata _deadlineBytes,
        IBatchExecution.Call[] calldata _calls
    ) internal returns (bytes[] memory) {
        // Hash the calls array to match the calldata version exactly
        // The calldata version uses keccak256(_calls) where _calls is abi.encode(IBatchExecution.Call[])
        // So we need to hash the encoded calls array
        bytes32 executionsHash = _hashCallArray(_calls); // checks the batch size
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

        bytes[] memory results = new bytes[](length);
        for (uint256 i; i < length;) {
            IBatchExecution.Call calldata execution = _calls[i];
            (bool success, bytes memory result) = execution.to.call{value: execution.value}(execution.data);
            if (!success) {
                revert ExecutionFailed();
            }
            results[i] = result;
            unchecked {
                ++i;
            }
        }
        return results;
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
        bytes32 executionsHash = _hashCallArray(_calls); // checks the batch size
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

    function _executeBatch(
        bytes calldata _signature,
        bytes calldata _nonceBytes,
        bytes calldata _deadlineBytes,
        bytes calldata _calls
    ) internal returns (bytes[] memory) {
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

        bytes32 executionsHash = _hashCallArray(calls); // checks the batch size
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
        return results;
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

        bytes32 executionsHash = _hashCallArray(calls); // checks the batch size
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

    function _hashCallArray(IBatchExecution.Call[] calldata _calls) internal pure returns (bytes32) {
        assembly {
            let length := _calls.length
            if gt(sub(length, 1), sub(MAX_BATCH_SIZE, 1)) {
                mstore(0x00, BATCH_SIZE_INVALID_SELECTOR)
                revert(0x00, 0x04)
            }
        }
        return _hashCallArrayUnchecked(_calls);
    }

    function _hashCallArrayUnchecked(IBatchExecution.Call[] calldata _calls) internal pure returns (bytes32) {
        bytes32 hash;
        assembly {
            let length := _calls.length
            let inlineHashesPtr := mload(0x40)
            let inlineHashesLength := mul(length, 0x20)
            mstore(0x40, add(inlineHashesPtr, inlineHashesLength)) // leave word for each hash inline

            let ptr := mload(0x40) // workspace -- this will be overwritten many times -- and is free to be overwritten after the loop
            mstore(ptr, CALL_TYPEHASH)
            let workspacePtr := add(ptr, 0x20)

            for { let i := 0 } lt(i, length) { i := add(i, 1) } {
                // Read the offset value for call[i]
                let offsetValue := calldataload(add(_calls.offset, mul(i, 0x20)))
                let startN := add(_calls.offset, offsetValue)

                let to := calldataload(startN)
                let value := calldataload(add(startN, 0x20))

                let dataRelOffset := calldataload(add(startN, 0x40))
                let dataLength := calldataload(add(startN, 0x60))
                let dataStart := add(startN, add(dataRelOffset, 0x20))

                calldatacopy(workspacePtr, dataStart, dataLength)
                let dataHash := keccak256(workspacePtr, dataLength)

                mstore(workspacePtr, to)
                mstore(add(workspacePtr, 0x20), value)
                mstore(add(workspacePtr, 0x40), dataHash)
                let structHash := keccak256(ptr, 0x80)

                mstore(add(inlineHashesPtr, mul(i, 0x20)), structHash)
            }

            hash := keccak256(inlineHashesPtr, inlineHashesLength)
        }

        return hash;
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

    /// @notice Computes the EIP-712 typed data hash for burning a nonce
    /// @dev Used to generate the hash that must be signed to invalidate a nonce
    /// @param _nonce The nonce value to burn
    /// @return The EIP-712 compliant hash to be signed
    function hashBurnNonce(uint128 _nonce) external view returns (bytes32) {
        bytes32 hash;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, BURN_NONCE_TYPEHASH)
            mstore(add(ptr, 0x20), _nonce)
            hash := keccak256(ptr, 0x40)
            mstore(0x40, add(ptr, 0x40)) // Update free memory pointer
        }
        return _hashTypedData(hash);
    }

    /// @notice Computes the EIP-712 typed data hash for approve-then-execute
    /// @dev Used to generate the hash for ERC20 approval followed by contract execution
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
    ) external view returns (bytes32) {
        bytes32 hash;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, APPROVE_THEN_EXECUTE_TYPEHASH)
            // Store nonce as 32-byte value (same as internal function)
            mstore(add(ptr, 0x20), _nonce)
            mstore(add(ptr, 0x40), _deadline)
            mstore(add(ptr, 0x60), _erc20Contract)
            mstore(add(ptr, 0x80), _spender)
            mstore(add(ptr, 0xa0), _approveAmount)
            mstore(add(ptr, 0xc0), _to)
            mstore(add(ptr, 0xe0), _value)
            // Compute argsHash in assembly
            let argsPtr := add(ptr, 0x100)
            calldatacopy(argsPtr, _data.offset, _data.length)
            let argsHash := keccak256(argsPtr, _data.length)
            mstore(add(ptr, 0x100), argsHash)
            // total = 0x120 (288) bytes
            hash := keccak256(ptr, 0x120)
            mstore(0x40, add(ptr, 0x120))
        }
        return _hashTypedData(hash);
    }

    /// @notice Computes the EIP-712 typed data hash for a session execution
    /// @dev Sessions allow specific senders to execute transactions to specific contracts
    /// @param _counter The session counter for replay protection
    /// @param _deadline The Unix timestamp after which the signature expires
    /// @param _sender The address authorized to execute in this session
    /// @param _to The contract that can be called in this session
    /// @return The EIP-712 compliant hash to be signed
    function hashSessionExecution(uint128 _counter, uint32 _deadline, address _sender, address _to)
        external
        view
        returns (bytes32)
    {
        bytes32 hash;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, SESSION_EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _counter)
            mstore(add(ptr, 0x40), _deadline)
            mstore(add(ptr, 0x60), _sender)
            mstore(add(ptr, 0x80), _to)
            hash := keccak256(ptr, 0xa0)
            mstore(0x40, add(ptr, 0xa0))
        }
        return _hashTypedData(hash);
    }

    /// @notice Computes the EIP-712 typed data hash for an arbitrary session execution
    /// @dev Arbitrary sessions allow senders to execute transactions to any contract
    /// @param _counter The session counter for replay protection
    /// @param _deadline The Unix timestamp after which the signature expires
    /// @param _sender The address authorized to execute arbitrary transactions
    /// @return The EIP-712 compliant hash to be signed
    function hashArbitrarySessionExecution(uint128 _counter, uint32 _deadline, address _sender)
        external
        view
        returns (bytes32)
    {
        bytes32 hash;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, ARBITRARY_SESSION_EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _counter)
            mstore(add(ptr, 0x40), _deadline)
            mstore(add(ptr, 0x60), _sender)
            hash := keccak256(ptr, 0x80)
            mstore(0x40, add(ptr, 0x80))
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

    /// @notice Computes the EIP-712 typed data hash for burning a session counter
    /// @dev Used to generate the hash that must be signed to revoke session permissions
    /// @param _counter The session counter value to burn
    /// @return The EIP-712 compliant hash to be signed
    function hashBurnSessionCounter(uint128 _counter) external view returns (bytes32) {
        bytes32 hash;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, BURN_SESSION_COUNTER_TYPEHASH)
            mstore(add(ptr, 0x20), _counter)
            hash := keccak256(ptr, 0x40)
            mstore(0x40, add(ptr, 0x40)) // Update free memory pointer
        }
        return _hashTypedData(hash);
    }
}
