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
    error InvalidToContract();
    error InvalidNonce();
    error InvalidCounter();
    error NotSelf();
    error ExecutionFailed();
    error UnsupportedExecutionMode();
    error ApprovalFailed();
    error ApprovalTo0Failed();
    error ApprovalReturnFalse();

    // Precomputed selector for DeadlineExceeded(): 0x559895a3
    bytes4 internal constant DEADLINE_EXCEEDED_SELECTOR = 0x559895a3;
    bytes4 internal constant APPROVAL_FAILED_SELECTOR = 0x8164f842;
    bytes4 internal constant APPROVAL_TO_0_FAILED_SELECTOR = 0xe12092fc;
    bytes4 internal constant APPROVAL_RETURN_FALSE_SELECTOR = 0xf572481d;
    uint8 public constant MAX_BATCH_SIZE = 20;

    bytes32 internal constant EXECUTION_TYPEHASH = 0x06bb52ccb5d61c4f9c5baafc0affaba32c4d02864c91221ad411291324aeea2e;
    // keccak256("Execution(uint128 nonce,uint32 deadline,address to,uint256 value,bytes data)")

    bytes32 internal constant APPROVE_THEN_EXECUTE_TYPEHASH =
        0x321d2e8c030c2c64001a1895d0f865dd0dc361666bd775ccb835b1a8bc2d41e3;
    // keccak256("ApproveThenExecute(uint128 nonce,uint32 deadline,address erc20Contract,address spender,uint256 approveAmount,address to,uint256 value,bytes data)")

    bytes32 internal constant BATCH_EXECUTION_TYPEHASH =
        0x14007e8c5dd696e52899952d0c28098ab95c056d082adc0d757f91c1306c7f55;
    // keccak256("BatchExecution(uint128 nonce,uint32 deadline,Call[] calls)Call(address to,uint256 value,bytes data)")

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

    struct State {
        uint128 nonce;
        mapping(bytes16 => bool) expiredSessionCounters;
    }

    bytes32 internal constant STATE_STORAGE_POSITION =
        0x34d5be385818fa5c8c4e7f9d5a028251d28ebab8aaf203a072d1dde2d49a1100;
    // Original: abi.encode(uint256(keccak256("TKGasDelegate.state")) - 1) & ~bytes32(uint256(0xff))

    function _getStateStorage() internal pure returns (State storage $) {
        assembly {
            $.slot := STATE_STORAGE_POSITION
        }
    }

    function nonce() external view returns (uint128) {
        return _getStateStorage().nonce;
    }

    function checkSessionCounterExpired(uint128 _counter) external view returns (bool) {
        return _getStateStorage().expiredSessionCounters[bytes16(_counter)];
    }

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
            assembly {
                outputContractBytes.offset := nonceEnd
                outputContractBytes.length := 20
                let loaded := calldataload(add(nonceEnd, 20))
                ethAmount := shr(176, loaded)
                arguments.offset := add(nonceEnd, 30)
                arguments.length := sub(calldatasize(), add(nonceEnd, 30))
            }
            if (ethAmount == 0) {
                address outputContract;
                assembly {
                    outputContract := shr(96, calldataload(nonceEnd))
                }
                _executeNoValueNoReturn(signature, nonceBytes, deadlineBytes, outputContract, arguments);
            } else {
                address outputContract;
                assembly {
                    outputContract := shr(96, calldataload(nonceEnd))
                }
                _executeWithValueNoReturn(signature, nonceBytes, deadlineBytes, outputContract, ethAmount, arguments);
            }
            assembly {
                return(0x00, 0x00)
            }
        } else if (functionSelector == bytes1(0x10)) {
            // approveThenExecute no return
            _approveThenExecuteNoReturn(
                signature,
                nonceBytes,
                deadlineBytes,
                msg.data[nonceEnd:nonceEnd + 20], //erc20Bytes
                msg.data[nonceEnd + 20:nonceEnd + 40], //spenderBytes
                msg.data[nonceEnd + 40:nonceEnd + 72], //approveAmountBytes
                msg.data[nonceEnd + 72:nonceEnd + 92], //outputContractBytes
                msg.data[nonceEnd + 92:nonceEnd + 102], //ethAmountBytes (10 bytes)
                msg.data[nonceEnd + 102:] //arguments
            );
            assembly {
                return(0x00, 0x00)
            }
        } else if (functionSelector == bytes1(0x20)) {
            // executeBatch no return
            _executeBatchNoReturn(signature, nonceBytes, deadlineBytes, msg.data[nonceEnd:]);
            assembly {
                return(0x00, 0x00)
            }
        } else if (functionSelector == bytes1(0x30)) {
            uint256 ethAmount;
            bytes calldata arguments;
            assembly {
                let w := calldataload(107) // Updated offset for deadline
                ethAmount := shr(176, w) // (32-10)*8
                arguments.offset := add(107, 10) // Skip the 10-byte ethAmount
                arguments.length := sub(calldatasize(), add(107, 10))
            }
            _executeSessionWithValueNoReturn(
                signature, nonceBytes, deadlineBytes, msg.data[nonceEnd:nonceEnd + 20], ethAmount, arguments
            );
            assembly {
                return(0x00, 0x00)
            }
        } else if (functionSelector == bytes1(0x40)) {
            // executeBatchSession no return
            IBatchExecution.Call[] calldata calls;
            assembly {
                calls.offset := add(107, 0x40) // Updated offset for deadline
                calls.length := calldataload(add(107, 0x20))
            }
            _executeBatchSessionNoReturn(signature, nonceBytes, deadlineBytes, msg.data[nonceEnd:nonceEnd + 20], calls);
            assembly {
                return(0x00, 0x00)
            }
        } else if (functionSelector == bytes1(0x50)) {
            // executeSessionArbitraryWithValue no return
            uint256 ethAmount;
            bytes calldata arguments;
            assembly {
                let loaded := calldataload(107) // Updated offset for deadline
                ethAmount := shr(176, loaded)
                arguments.offset := add(107, 10) // Skip the 10-byte ethAmount
                arguments.length := sub(calldatasize(), add(107, 10))
            }
            _executeSessionArbitraryWithValueNoReturn(
                signature, nonceBytes, deadlineBytes, msg.data[nonceEnd:nonceEnd + 20], ethAmount, arguments
            );
            assembly {
                return(0x00, 0x00)
            }
        } else if (functionSelector == bytes1(0x60)) {
            // executeBatchSessionArbitrary
            IBatchExecution.Call[] calldata calls;
            assembly {
                calls.offset := add(87, 0x40) // Updated offset for deadline (no outputContract)
                calls.length := calldataload(add(87, 0x20))
            }
            _executeBatchSessionArbitraryNoReturn(signature, nonceBytes, deadlineBytes, calls);
            assembly {
                return(0x00, 0x00)
            }
        }
        // RETURN PATHS (0xX1) - Checked after no-return paths
        else if (functionSelector == bytes1(0x01)) {
            // execute (with return) - handles both with and without value
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
            bytes memory result;
            if (ethAmount == 0) {
                result = _executeNoValue(signature, nonceBytes, deadlineBytes, outputContract, arguments);
            } else {
                result = _executeWithValue(signature, nonceBytes, deadlineBytes, outputContract, ethAmount, arguments);
            }
            return result;
        } else if (functionSelector == bytes1(0x11)) {
            // approveThenExecute with return

            address outputContract;
            uint256 ethAmount;
            assembly {
                outputContract := shr(96, calldataload(159)) // Updated offset for deadline
                let loaded := calldataload(179) // Updated offset for deadline
                ethAmount := shr(176, loaded)
            }
            bytes memory result = _approveThenExecute(
                signature,
                nonceBytes,
                deadlineBytes,
                msg.data[nonceEnd:nonceEnd + 20], //erc20Bytes
                msg.data[nonceEnd + 20:nonceEnd + 40], //spenderBytes
                msg.data[nonceEnd + 40:nonceEnd + 72], //approveAmountBytes
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
            assembly {
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
            assembly {
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
            assembly {
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
            assembly {
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
        if (ECDSA.recoverCalldata(_hash, _signature) != address(this)) {
            revert NotSelf();
        }
    }

    function validateSignature(bytes32 _hash, bytes calldata _signature) external view returns (bool) {
        _requireSelf(_hash, _signature);
        return true;
    }

    function _consumeNonce(bytes calldata _nonceBytes) internal {
        uint128 nonceValue;
        State storage state = _getStateStorage();
        assembly {
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

    function getDomainSeparator() external view returns (bytes32) {
        return _domainSeparator();
    }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "TKGasDelegate";
        version = "1";
    }

    function executeReturns(address _to, uint256 _value, bytes calldata _data) external returns (bytes memory) {
        bytes memory result = _value == 0
            ? _executeNoValue(_data[0:65], _data[65:81], _data[81:85], _to, _data[85:])
            : _executeWithValue(_data[0:65], _data[65:81], _data[81:85], _to, _value, _data[85:]);
        return result;
    }

    function execute(address _to, uint256 _value, bytes calldata _data) external {
        _value == 0
            ? _executeNoValueNoReturn(_data[0:65], _data[65:81], _data[81:85], _to, _data[85:])
            : _executeWithValueNoReturn(_data[0:65], _data[65:81], _data[81:85], _to, _value, _data[85:]);
    }

    function executeReturns(bytes calldata data) external returns (bytes memory) {
        address to;
        uint256 value;
        assembly {
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

    function execute(bytes calldata data) external {
        address to;
        uint256 value;
        assembly {
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

    function executeNoValueNoReturn(bytes calldata data) external {
        address to;
        assembly {
            // address is 20 bytes immediately after deadline
            to := shr(96, calldataload(add(data.offset, 85)))
        }
        _executeNoValueNoReturn(data[0:65], data[65:81], data[81:85], to, data[105:]);
    }

    function approveThenExecuteReturns(bytes calldata _data) external returns (bytes memory) {
        // Layout: [signature(65)][nonce(16)][deadline(4)][erc20(20)][spender(20)][approveAmount(32)][output(20)][eth(32)][args]
        address to;
        uint256 value;
        assembly {
            to := shr(96, calldataload(add(_data.offset, 157)))
            value := calldataload(add(_data.offset, 177))
        }
        bytes memory result = _approveThenExecute(
            _data[0:65],
            _data[65:81],
            _data[81:85], // deadline bytes
            _data[85:105], // erc20 bytes
            _data[105:125], // spender bytes
            _data[125:157], // approveAmount bytes
            to,
            value,
            _data[209:]
        );
        return result;
    }

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

    function _approveThenExecute(
        bytes calldata _signature, // 65 bytes
        bytes calldata _nonceBytes, // uint128
        bytes calldata _deadlineBytes, // uint32
        bytes calldata _erc20Bytes, // address (20 bytes)
        bytes calldata _spenderBytes, // address
        bytes calldata _approveAmountBytes, // uint256
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments
    ) internal returns (bytes memory) {
        bytes32 hash;
        assembly {
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
            // erc20 address right-aligned in 32 bytes
            let erc20Raw := calldataload(_erc20Bytes.offset)
            mstore(add(ptr, 0x60), shr(96, erc20Raw))
            // Write spender (20 bytes right-aligned in 32 bytes)
            let spenderRaw := calldataload(_spenderBytes.offset)
            mstore(add(ptr, 0x80), shr(96, spenderRaw))
            // Write approveAmount (32 bytes)
            calldatacopy(add(ptr, 0xa0), _approveAmountBytes.offset, 32)
            mstore(add(ptr, 0xc0), _outputContract)
            mstore(add(ptr, 0xe0), _ethAmount)
            // Compute argsHash in assembly
            let argsPtr := add(ptr, 0x100)
            calldatacopy(argsPtr, _arguments.offset, _arguments.length)
            let argsHash := keccak256(argsPtr, _arguments.length)
            mstore(add(ptr, 0x100), argsHash)
            // total = 0x120 (288) bytes
            hash := keccak256(ptr, 0x120)
        }
        hash = _hashTypedData(hash);

        _validateExecute(hash, _signature, _nonceBytes);
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
            let approveReturnPtr := mload(0x40)
            let success := call(gas(), token, 0, ptr, 0x44, approveReturnPtr, 0x20)
            switch success
            case 0 {
                // attempt a special case for usdt on eth mainnet usually requires resetting approval to 0 then setting it again
                //mstore(ptr, shl(224, 0x095ea7b3)) // IERC20.approve selector
                //calldatacopy(add(ptr, 0x10), _spenderBytes.offset, 20)
                mstore(add(ptr, 0x24), 0) // essentially write nothing to the next word in the register so it's 0
                if iszero(call(gas(), token, 0, ptr, 0x44, 0, 0)) {
                    let errorPtr := mload(0x40)
                    mstore(errorPtr, APPROVAL_TO_0_FAILED_SELECTOR)
                    revert(errorPtr, 0x04)
                }
                calldatacopy(add(ptr, 0x24), _approveAmountBytes.offset, 32) // then write something
                if iszero(call(gas(), token, 0, ptr, 0x44, approveReturnPtr, 0x20)) {
                    let errorPtr := mload(0x40)
                    mstore(errorPtr, APPROVAL_FAILED_SELECTOR)
                    revert(errorPtr, 0x04)
                }
            }
            if iszero(or(iszero(returndatasize()), mload(approveReturnPtr))) {
                let errorPtr := mload(0x40)
                mstore(errorPtr, APPROVAL_RETURN_FALSE_SELECTOR)
                revert(errorPtr, 0x04)
            }
        }
        (bool success, bytes memory result) =
            _ethAmount == 0 ? _outputContract.call(_arguments) : _outputContract.call{value: _ethAmount}(_arguments);
        if (success) {
            return result;
        }
        revert ExecutionFailed();
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
        assembly {
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
        }
        hash = _hashTypedData(hash);

        _validateExecute(hash, _signature, _nonceBytes);

        // Build calldata for approve(spender, amount) and call token
        assembly {
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
        assembly {
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
        }
        hash = _hashTypedData(hash);

        _validateExecute(hash, _signature, _nonceBytes);

        // Build calldata for approve(spender, amount) and call token
        assembly {
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
        }

        // Execute the call without returning the result
        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, _arguments.offset, _arguments.length)
            if iszero(call(gas(), _outputContract, _ethAmount, ptr, _arguments.length, 0, 0)) { revert(0, 0) }
        }
    }

    function _approveThenExecuteNoReturn(
        bytes calldata _signature, // 65 bytes
        bytes calldata _nonceBytes, // uint128
        bytes calldata _deadlineBytes, // uint32
        bytes calldata _erc20Bytes, // address (20 bytes)
        bytes calldata _spenderBytes, // address (20 bytes)
        bytes calldata _approveAmountBytes, // uint256 (32 bytes)
        bytes calldata _outputContractBytes, // address (20 bytes)
        bytes calldata _ethAmountBytes,
        bytes calldata _arguments
    ) internal {
        bytes32 hash;
        assembly {
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
            // erc20 address right-aligned in 32 bytes
            let erc20Raw := calldataload(_erc20Bytes.offset)
            mstore(add(ptr, 0x60), shr(96, erc20Raw))
            // spender address right-aligned in 32 bytes
            let spenderRaw := calldataload(_spenderBytes.offset)
            mstore(add(ptr, 0x80), shr(96, spenderRaw))
            // approve amount (32 bytes)
            calldatacopy(add(ptr, 0xa0), _approveAmountBytes.offset, 32)
            // output contract right-aligned
            let outRaw := calldataload(_outputContractBytes.offset)
            mstore(add(ptr, 0xc0), shr(96, outRaw))
            // eth amount (right-align arbitrary length up to 32 bytes)
            {
                let rawEth := calldataload(_ethAmountBytes.offset)
                let shiftBits := mul(sub(32, _ethAmountBytes.length), 8)
                let ethVal := shr(shiftBits, rawEth)
                mstore(add(ptr, 0xe0), ethVal)
            }
            // args hash
            let argsPtr := add(ptr, 0x100)
            calldatacopy(argsPtr, _arguments.offset, _arguments.length)
            let argsHash := keccak256(argsPtr, _arguments.length)
            mstore(add(ptr, 0x100), argsHash)
            hash := keccak256(ptr, 0x120)
        }
        hash = _hashTypedData(hash);

        _validateExecute(hash, _signature, _nonceBytes);

        // approve then execute; single assembly block to minimize overhead
        assembly {
            // Approve
            let token := shr(96, calldataload(_erc20Bytes.offset))
            let ptr := mload(0x40)
            mstore(ptr, shl(224, 0x095ea7b3)) // IERC20.approve selector
            calldatacopy(add(ptr, 0x10), _spenderBytes.offset, 20)
            calldatacopy(add(ptr, 0x24), _approveAmountBytes.offset, 32)
            let approveReturnPtr := mload(0x40)
            let success := call(gas(), token, 0, ptr, 0x44, approveReturnPtr, 0x20)
            switch success
            case 0 {
                // attempt a special case for usdt on eth mainnet usually requires resetting approval to 0 then setting it again
                //mstore(ptr, shl(224, 0x095ea7b3)) // IERC20.approve selector
                //calldatacopy(add(ptr, 0x10), _spenderBytes.offset, 20)
                mstore(add(ptr, 0x24), 0) // essentially write nothing to the next word in the register so it's 0
                if iszero(call(gas(), token, 0, ptr, 0x44, 0, 0)) {
                    let errorPtr := mload(0x40)
                    mstore(errorPtr, APPROVAL_TO_0_FAILED_SELECTOR)
                    revert(errorPtr, 0x04)
                }
                calldatacopy(add(ptr, 0x24), _approveAmountBytes.offset, 32) // then write something
                if iszero(call(gas(), token, 0, ptr, 0x44, approveReturnPtr, 0x20)) {
                    let errorPtr := mload(0x40)
                    mstore(errorPtr, APPROVAL_FAILED_SELECTOR)
                    revert(errorPtr, 0x04)
                }
            }
            if iszero(or(iszero(returndatasize()), mload(approveReturnPtr))) {
                let errorPtr := mload(0x40)
                mstore(errorPtr, APPROVAL_RETURN_FALSE_SELECTOR)
                revert(errorPtr, 0x04)
            }
            // Execute
            let outputAddr := shr(96, calldataload(_outputContractBytes.offset))
            calldatacopy(ptr, _arguments.offset, _arguments.length)
            let rawEth := calldataload(_ethAmountBytes.offset)
            let shiftBits := mul(sub(32, _ethAmountBytes.length), 8)
            let ethVal := shr(shiftBits, rawEth)
            if iszero(call(gas(), outputAddr, ethVal, ptr, _arguments.length, 0, 0)) { revert(0, 0) }
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
        assembly {
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
        }
        hash = _hashTypedData(hash);

        _validateExecute(hash, _signature, _nonceBytes);

        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, _arguments.offset, _arguments.length)
            if iszero(call(gas(), _outputContract, 0, ptr, _arguments.length, 0, 0)) { revert(0, 0) }
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
        assembly {
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
        assembly {
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
        bytes calldata _outputContractBytes,
        uint256 _ethAmount,
        bytes calldata _arguments
    ) internal {
        bytes32 argsHash = keccak256(_arguments);
        bytes32 hash; // all this assembly to avoid using abi.encode
        assembly {
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
            let raw := calldataload(_outputContractBytes.offset)
            mstore(add(ptr, 0x60), shr(96, raw))
            mstore(add(ptr, 0x80), _ethAmount)
            mstore(add(ptr, 0xa0), argsHash)
            hash := keccak256(ptr, 0xc0)
        }
        hash = _hashTypedData(hash);

        _validateExecute(hash, _signature, _nonceBytes);
        assembly {
            let outputContract := shr(96, calldataload(_outputContractBytes.offset))
            let ptr := mload(0x40)
            calldatacopy(ptr, _arguments.offset, _arguments.length)
            if iszero(call(gas(), outputContract, _ethAmount, ptr, _arguments.length, 0, 0)) { revert(0, 0) }
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
        assembly {
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
        }
        hash = _hashTypedData(hash);

        _validateExecute(hash, _signature, _nonceBytes);
        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, _arguments.offset, _arguments.length)
            if iszero(call(gas(), _outputContract, _ethAmount, ptr, _arguments.length, 0, 0)) { revert(0, 0) }
        }
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
            ++_getStateStorage().nonce;
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
        assembly {
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
            mstore(0x40, add(ptr, 0xa0)) // Update free memory pointer
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
        assembly {
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
        }
        hash = _hashTypedData(hash);

        _validateSession(hash, _signature, _counterBytes);
        assembly {
            let outputContract := shr(96, calldataload(_outputContractBytes.offset))
            let ptr := mload(0x40)
            calldatacopy(ptr, _arguments.offset, _arguments.length)
            if iszero(call(gas(), outputContract, _ethAmount, ptr, _arguments.length, 0, 0)) { revert(0, 0) }
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
        assembly {
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
        }
        hash = _hashTypedData(hash);

        _validateSession(hash, _signature, _counterBytes);
        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, _arguments.offset, _arguments.length)
            if iszero(call(gas(), _outputContract, _ethAmount, ptr, _arguments.length, 0, 0)) { revert(0, 0) }
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

        if (_calls.length > MAX_BATCH_SIZE) {
            revert BatchSizeExceeded();
        }

        bytes32 hash;
        assembly {
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
            mstore(0x40, add(ptr, 0xa0)) // Update free memory pointer
        }
        hash = _hashTypedData(hash);
        _validateSession(hash, _signature, _counterBytes);

        // Execute the session transaction
        uint256 length = _calls.length;
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
        if (_calls.length > MAX_BATCH_SIZE) {
            revert BatchSizeExceeded();
        }
        bytes32 hash;
        assembly {
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
        }
        hash = _hashTypedData(hash);
        _validateSession(hash, _signature, _counterBytes);

        address _out = address(uint160(uint256(bytes32(msg.data)))); // placeholder to avoid warnings
        _out; // silence
        uint256 length = _calls.length;
        for (uint256 i = 0; i < length;) {
            IBatchExecution.Call calldata execution = _calls[i];
            uint256 ethAmount = execution.value;
            address outputContract = execution.to;
            if (bytes20(outputContract) != bytes20(_outputContractBytes)) {
                revert InvalidToContract();
            }
            bytes calldata _callData = execution.data;
            assembly {
                let ptr := mload(0x40)
                calldatacopy(ptr, _callData.offset, _callData.length)
                if iszero(call(gas(), outputContract, ethAmount, ptr, _callData.length, 0, 0)) { revert(0, 0) }
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
        if (_calls.length > MAX_BATCH_SIZE) {
            revert BatchSizeExceeded();
        }

        address sender = msg.sender;
        bytes32 hash;
        assembly {
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
            mstore(add(ptr, 0x60), sender)
            mstore(add(ptr, 0x80), _outputContract)
            hash := keccak256(ptr, 0xa0)
            mstore(0x40, add(ptr, 0xa0)) // Update free memory pointer
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

            assembly {
                let ptr := mload(0x40)
                calldatacopy(ptr, _callData.offset, _callData.length)
                if iszero(call(gas(), outputContract, ethAmount, ptr, _callData.length, 0, 0)) { revert(0, 0) }
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
        assembly {
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
        assembly {
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
        }
        hash = _hashTypedData(hash);
        _validateSession(hash, _signature, _counterBytes);
        assembly {
            let outputContract := shr(96, calldataload(_outputContractBytes.offset))
            let ptr := mload(0x40)
            calldatacopy(ptr, _arguments.offset, _arguments.length)
            if iszero(call(gas(), outputContract, _ethAmount, ptr, _arguments.length, 0, 0)) { revert(0, 0) }
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
        assembly {
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
        }
        hash = _hashTypedData(hash);
        _validateSession(hash, _signature, _counterBytes);
        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, _arguments.offset, _arguments.length)
            if iszero(call(gas(), _outputContract, _ethAmount, ptr, _arguments.length, 0, 0)) { revert(0, 0) }
        }
    }

    function _executeBatchSessionArbitrary(
        bytes calldata _signature,
        bytes calldata _counterBytes,
        bytes calldata _deadlineBytes, // Changed from uint128
        IBatchExecution.Call[] calldata _calls
    ) internal returns (bytes[] memory) {
        if (_calls.length > MAX_BATCH_SIZE) {
            revert BatchSizeExceeded();
        }
        bytes32 hash;
        assembly {
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
        }
        hash = _hashTypedData(hash);
        _validateSession(hash, _signature, _counterBytes);
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

        return results;
    }

    function _executeBatchSessionArbitraryNoReturn(
        bytes calldata _signature,
        bytes calldata _counterBytes,
        bytes calldata _deadlineBytes,
        IBatchExecution.Call[] calldata _calls
    ) internal {
        if (_calls.length > MAX_BATCH_SIZE) revert BatchSizeExceeded();
        bytes32 hash;
        assembly {
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
        }
        hash = _hashTypedData(hash);
        _validateSession(hash, _signature, _counterBytes);

        uint256 length = _calls.length;
        for (uint256 i = 0; i < length;) {
            IBatchExecution.Call calldata execution = _calls[i];
            uint256 ethAmount = execution.value;
            address outputContract = execution.to;
            bytes calldata _callData = execution.data;
            assembly {
                let ptr := mload(0x40)
                calldatacopy(ptr, _callData.offset, _callData.length)
                if iszero(call(gas(), outputContract, ethAmount, ptr, _callData.length, 0, 0)) { revert(0, 0) }
            }
            unchecked {
                ++i;
            }
        }
    }

    function burnSessionCounter(bytes calldata _signature, uint128 _counter) external {
        bytes32 hash;
        assembly {
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

    function burnSessionCounter(uint128 _counter) external {
        if (msg.sender != address(this) || msg.sender != tx.origin) {
            revert NotSelf();
        }
        _getStateStorage().expiredSessionCounters[bytes16(_counter)] = true; // does not need to check if the counter is already expired
    }

    function executeSessionReturns(bytes calldata data) external returns (bytes memory) {
        // Layout: [signature(65)][counter(16)][deadline(4)][output(20)][ethAmount(32)][args]
        address output;
        uint256 ethAmount;
        assembly {
            output := shr(96, calldataload(add(data.offset, 85)))
            ethAmount := calldataload(add(data.offset, 105))
        }
        bytes memory result =
            _executeSessionWithValue(data[0:65], data[65:81], data[81:85], output, ethAmount, data[137:]);
        return result;
    }

    function executeSessionReturns(address _to, uint256 _value, bytes calldata _data) external returns (bytes memory) {
        bytes memory result = _executeSessionWithValue(_data[0:65], _data[65:81], _data[81:85], _to, _value, _data[85:]);
        return result;
    }

    function executeSession(address _to, uint256 _value, bytes calldata _data) external {
        _executeSessionWithValueNoReturn(_data[0:65], _data[65:81], _data[81:85], _to, _value, _data[85:]);
    }

    function executeBatchSessionReturns(bytes calldata data) external returns (bytes[] memory) {
        // Layout: [signature(65)][counter(16)][deadline(4)][output(20)][abi.encode(IBatchExecution.Call[])]
        IBatchExecution.Call[] calldata calls;
        address output;
        assembly {
            output := shr(96, calldataload(add(data.offset, 85)))

            // ABI: at offset 105, we have the head for the dynamic array: [offset=0x20][length][elements]
            calls.offset := add(data.offset, add(105, 0x40))
            calls.length := calldataload(add(data.offset, add(105, 0x20)))
        }
        bytes[] memory results = _executeBatchSession(data[0:65], data[65:81], data[81:85], output, calls);
        return results;
    }

    function executeBatchSessionReturns(IBatchExecution.Call[] calldata _calls, bytes calldata _data)
        external
        returns (bytes[] memory)
    {
        address output;
        assembly {
            output := shr(96, calldataload(add(_data.offset, 85)))
        }
        bytes[] memory results = _executeBatchSession(_data[0:65], _data[65:81], _data[81:85], output, _calls);
        return results;
    }

    function executeBatchSession(IBatchExecution.Call[] calldata _calls, bytes calldata _data) external {
        address output;
        assembly {
            output := shr(96, calldataload(add(_data.offset, 85)))
        }
        _executeBatchSessionNoReturn(_data[0:65], _data[65:81], _data[81:85], output, _calls);
    }

    function executeSessionArbitraryReturns(bytes calldata data) external returns (bytes memory) {
        // does not limit output contract
        // Layout: [signature(65)][counter(16)][deadline(4)][output(20)][ethAmount(32)][args]
        address output;
        uint256 ethAmount;
        assembly {
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

    function executeBatchSessionArbitraryReturns(bytes calldata data) external returns (bytes[] memory) {
        // Layout: [signature(65)][counter(16)][deadline(4)][abi.encode(IBatchExecution.Call[])]
        IBatchExecution.Call[] calldata calls;
        assembly {
            // ABI: at offset 85, we have the head for the dynamic array: [offset=0x20][length][elements]
            calls.offset := add(data.offset, add(85, 0x40))
            calls.length := calldataload(add(data.offset, add(85, 0x20)))
        }
        // For arbitrary batch, sender is implicitly msg.sender in typehash, keep as paymaster (msg.sender)
        bytes[] memory results = _executeBatchSessionArbitrary(data[0:65], data[65:81], data[81:85], calls);
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

    // Missing bytes-only no-return functions
    function approveThenExecute(bytes calldata data) external {
        _approveThenExecuteNoReturn(
            data[0:65],
            data[65:81],
            data[81:85], // deadline bytes
            data[85:105], // erc20 bytes
            data[105:125], // spender bytes
            data[125:157], // approveAmount bytes
            data[157:177], // outputContract bytes
            data[177:209], // ethAmount bytes
            data[209:]
        );
    }

    function executeBatch(bytes calldata data) external {
        _executeBatchNoReturn(data[0:65], data[65:81], data[81:85], data[85:]);
    }

    function executeBatchSession(bytes calldata data) external {
        IBatchExecution.Call[] calldata calls;
        assembly {
            calls.offset := add(data.offset, add(105, 0x40))
            calls.length := calldataload(add(data.offset, add(105, 0x20)))
        }
        _executeBatchSessionNoReturn(data[0:65], data[65:81], data[81:85], data[85:105], calls);
    }

    function executeBatchSessionArbitrary(bytes calldata data) external {
        IBatchExecution.Call[] calldata calls;
        assembly {
            calls.offset := add(data.offset, add(85, 0x40))
            calls.length := calldataload(add(data.offset, add(85, 0x20)))
        }
        _executeBatchSessionArbitraryNoReturn(data[0:65], data[65:81], data[81:85], calls);
    }

    function executeSession(bytes calldata data) external {
        // Parse data to extract parameters and call appropriate internal function
        address to;
        uint256 value;
        assembly {
            to := shr(96, calldataload(add(data.offset, 85)))
            value := calldataload(add(data.offset, 105))
        }
        _executeSessionWithValueNoReturn(data[0:65], data[65:81], data[81:85], to, value, data[137:]);
    }

    function executeSessionArbitrary(bytes calldata data) external {
        // Parse data to extract parameters and call appropriate internal function
        address to;
        uint256 value;
        assembly {
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
        bytes32 executionsHash = keccak256(abi.encode(_calls));
        bytes32 hash;
        assembly {
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
            mstore(0x40, add(ptr, 0x80)) // Update free memory pointer
        }
        hash = _hashTypedData(hash);
        _validateExecute(hash, _signature, _nonceBytes);

        uint256 length = _calls.length;
        if (length > MAX_BATCH_SIZE) {
            revert BatchSizeExceeded();
        }

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
        bytes32 executionsHash = keccak256(abi.encode(_calls));
        bytes32 hash;
        assembly {
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
            mstore(0x40, add(ptr, 0x80)) // Update free memory pointer
        }
        hash = _hashTypedData(hash);
        _validateExecute(hash, _signature, _nonceBytes);

        uint256 length = _calls.length;
        if (length > MAX_BATCH_SIZE) {
            revert BatchSizeExceeded();
        }

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
        // Hash the raw encoded calls slice to match the off-chain preimage exactly
        bytes32 executionsHash = keccak256(_calls);
        bytes32 hash;
        assembly {
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
            mstore(0x40, add(ptr, 0x80)) // Update free memory pointer
        }
        hash = _hashTypedData(hash);
        _validateExecute(hash, _signature, _nonceBytes);

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
        return results;
    }

    function _executeBatchNoReturn(
        bytes calldata _signature,
        bytes calldata _nonceBytes,
        bytes calldata _deadlineBytes,
        bytes calldata _calls
    ) internal {
        bytes32 executionsHash = keccak256(_calls);
        bytes32 hash;
        assembly {
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

        IBatchExecution.Call[] calldata calls;
        uint256 length;
        assembly {
            calls.offset := add(_calls.offset, 0x40)
            calls.length := calldataload(add(_calls.offset, 0x20))
            length := calls.length
        }
        if (length > MAX_BATCH_SIZE) revert BatchSizeExceeded();
        for (uint256 i = 0; i < length;) {
            IBatchExecution.Call calldata execution = calls[i];
            uint256 ethAmount = execution.value;
            address outputContract = execution.to;
            bytes calldata _callData2 = execution.data;
            assembly {
                let ptr := mload(0x40)
                calldatacopy(ptr, _callData2.offset, _callData2.length)
                if iszero(call(gas(), outputContract, ethAmount, ptr, _callData2.length, 0, 0)) { revert(0, 0) }
            }
            unchecked {
                ++i;
            }
        }
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

    function supportsInterface(bytes4 _interfaceId) external pure returns (bool) {
        return _interfaceId == 0x01ffc9a7 // ERC165 Interface ID
            || _interfaceId == 0x150b7a02 // ERC721Receiver Interface ID
            || _interfaceId == 0x4e2312e0 // ERC1155Receiver Interface ID (onERC1155Received)
            || _interfaceId == 0xbc197c81; // ERC1155Receiver Interface ID (onERC1155BatchReceived)
    }

    // View functions
    function hashExecution(uint128 _nonce, uint32 _deadline, address _to, uint256 _value, bytes calldata _data)
        external
        view
        returns (bytes32)
    {
        bytes32 argsHash = keccak256(_data);
        bytes32 hash;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _nonce)
            mstore(add(ptr, 0x40), _deadline)
            mstore(add(ptr, 0x60), _to)
            mstore(add(ptr, 0x80), _value)
            mstore(add(ptr, 0xa0), argsHash)
            hash := keccak256(ptr, 0xc0)
            mstore(0x40, add(ptr, 0xc0)) // Update free memory pointer
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
        assembly {
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
            mstore(0x40, add(ptr, 0x120)) // Update free memory pointer
        }
        return _hashTypedData(hash);
    }

    function hashSessionExecution(uint128 _counter, uint32 _deadline, address _sender, address _to)
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
            mstore(add(ptr, 0x80), _to)
            hash := keccak256(ptr, 0xa0)
            mstore(0x40, add(ptr, 0xa0)) // Update free memory pointer
        }
        return _hashTypedData(hash);
    }

    function hashArbitrarySessionExecution(uint128 _counter, uint32 _deadline, address _sender)
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

    function hashBatchExecution(uint128 _nonce, uint32 _deadline, IBatchExecution.Call[] calldata _calls)
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
            mstore(add(ptr, 0x40), _deadline)
            mstore(add(ptr, 0x60), executionsHash)
            hash := keccak256(ptr, 0x80)
            mstore(0x40, add(ptr, 0x80)) // Update free memory pointer
        }
        return _hashTypedData(hash);
    }

    function hashBurnSessionCounter(uint128 _counter) external view returns (bytes32) {
        bytes32 hash;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, BURN_SESSION_COUNTER_TYPEHASH)
            mstore(add(ptr, 0x20), _counter)
            hash := keccak256(ptr, 0x40)
            mstore(0x40, add(ptr, 0x40)) // Update free memory pointer
        }
        return _hashTypedData(hash);
    }
}
