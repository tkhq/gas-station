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
    error UnsupportedExecutionMode();
    error ApprovalFailed();
    error ApprovalTo0Failed();

    // Precomputed selector for DeadlineExceeded(): 0x559895a3
    bytes4 private constant DEADLINE_EXCEEDED_SELECTOR = 0x559895a3;
    bytes4 private constant APPROVAL_FAILED_SELECTOR = 0x8164f842;
    bytes4 private constant APPROVAL_TO_0_FAILED_SELECTOR = 0xe12092fc;
    uint8 public constant MAX_BATCH_SIZE = 20;

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

    //bytes4 private constant APPROVE_SELECTOR = 0x095ea7b3;
    State public state;

    constructor() EIP712() {}

    fallback(bytes calldata) external returns (bytes memory) {
        bytes1 functionSelector = bytes1(msg.data[1]);

        bytes calldata signature = msg.data[2:67];
        bytes calldata nonceBytes = msg.data[67:83]; // Always 16 bytes - can also be the counter
        uint256 nonceEnd = 83; // Fixed offset after 16-byte nonce

        // NO RETURN PATHS (0xX0) - Checked first
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
        } else if (functionSelector == bytes1(0x10)) {
            // executeWithValue no return
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
            _executeWithValueNoReturn(signature, nonceBytes, outputContractBytes, ethAmount, arguments);
            assembly {
                return(0x00, 0x00)
            }
        } else if (functionSelector == bytes1(0x20)) {
            // approveThenExecute no return
            _approveThenExecuteNoReturn(
                signature,
                nonceBytes,
                msg.data[nonceEnd:103], //erc20Bytes
                msg.data[103:123], //spenderBytes
                msg.data[123:155], //approveAmountBytes
                msg.data[155:175], //outputContractBytes
                msg.data[175:185], //ethAmountBytes
                msg.data[185:] //arguments
            );
            assembly {
                return(0x00, 0x00)
            }
        } else if (functionSelector == bytes1(0x30)) {
            // executeBatch no return
            _executeBatchNoReturn(signature, nonceBytes, msg.data[nonceEnd:]);
            assembly {
                return(0x00, 0x00)
            }
        } else if (functionSelector == bytes1(0x40)) {
            uint256 ethAmount;
            assembly {
                let w := calldataload(107)
                ethAmount := shr(176, w) // (32-10)*8
            }
            _executeSessionWithValueNoReturn(
                signature, nonceBytes, msg.data[nonceEnd:87], msg.data[87:107], ethAmount, msg.data[117:]
            );
            assembly {
                return(0x00, 0x00)
            }
        } else if (functionSelector == bytes1(0x50)) {
            // executeBatchSession no return
            IBatchExecution.Call[] calldata calls;
            assembly {
                calls.offset := add(107, 0x40)
                calls.length := calldataload(add(107, 0x20))
            }
            _executeBatchSessionNoReturn(signature, nonceBytes, msg.data[nonceEnd:87], msg.data[87:107], calls);
            assembly {
                return(0x00, 0x00)
            }
        } else if (functionSelector == bytes1(0x60)) {
            // executeSessionArbitraryWithValue no return
            uint256 ethAmount;
            assembly {
                let loaded := calldataload(107)
                ethAmount := shr(176, loaded)
            }
            _executeSessionArbitraryWithValueNoReturn(
                signature, nonceBytes, msg.data[nonceEnd:87], msg.data[87:107], ethAmount, msg.data[117:]
            );
            assembly {
                return(0x00, 0x00)
            }
        } else if (functionSelector == bytes1(0x70)) {
            // executeBatchSessionArbitrary
            IBatchExecution.Call[] calldata calls;
            assembly {
                calls.offset := add(87, 0x40)
                calls.length := calldataload(add(87, 0x20))
            }
            _executeBatchSessionArbitraryNoReturn(signature, nonceBytes, msg.data[nonceEnd:87], calls);
            assembly {
                return(0x00, 0x00)
            }
        }
        // RETURN PATHS (0xX1) - Checked after no-return paths
        else if (functionSelector == bytes1(0x01)) {
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
        } else if (functionSelector == bytes1(0x21)) {
            // approveThenExecute with return

            address outputContract;
            uint256 ethAmount;
            assembly {
                outputContract := shr(96, calldataload(155))
                let loaded := calldataload(175)
                ethAmount := shr(176, loaded)
            }
            (, bytes memory result) = _approveThenExecute(
                signature,
                nonceBytes,
                msg.data[nonceEnd:103], //erc20Bytes
                msg.data[103:123], //spenderBytes
                msg.data[123:155], //approveAmountBytes
                outputContract, 
                ethAmount,
                msg.data[185:] //arguments
            );
            return result;
        } else if (functionSelector == bytes1(0x31)) {
            // executeBatch with return
            (, bytes[] memory result) = _executeBatch(signature, nonceBytes, msg.data[nonceEnd:]);
            return abi.encode(result);
        } else if (functionSelector == bytes1(0x41)) {
            address outputContract;
            uint256 ethAmount;
            assembly {
                outputContract := shr(96, calldataload(87))
                let w := calldataload(107)
                ethAmount := shr(176, w) // (32-10)*8
            }

            (, bytes memory result) =
                _executeSessionWithValue(signature, nonceBytes, msg.data[nonceEnd:87], outputContract, ethAmount, msg.data[117:]);
            return result;
        } else if (functionSelector == bytes1(0x51)) {
            // executeBatchSession with return
            address outputContract;
            IBatchExecution.Call[] calldata calls;
            assembly {
                outputContract := shr(96, calldataload(87))
                calls.offset := add(107, 0x40)
                calls.length := calldataload(add(107, 0x20))
            }

            (, bytes[] memory result) =
                _executeBatchSession(signature, nonceBytes, msg.data[nonceEnd:87], outputContract, calls);
            return abi.encode(result);
        } else if (functionSelector == bytes1(0x61)) {
            // executeSessionArbitraryWithValue with return
            address outputContract;
            uint256 ethAmount;
            assembly {
                outputContract := shr(96, calldataload(87))
                let loaded := calldataload(107)
                ethAmount := shr(176, loaded)
            }
            (, bytes memory result) = _executeSessionArbitraryWithValue(
                signature, nonceBytes, msg.data[nonceEnd:87], outputContract, ethAmount, msg.data[117:]
            );
            return result;
        } else if (functionSelector == bytes1(0x71)) {
            // executeBatchSessionArbitrary with return
            IBatchExecution.Call[] calldata calls;
            assembly {
               calls.offset := add(87, 0x40)
                calls.length := calldataload(add(87, 0x20))
            }
            (, bytes[] memory result) = _executeBatchSessionArbitrary(signature, nonceBytes, msg.data[nonceEnd:87], calls);
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

    function execute(address _to, uint256 _ethAmount, bytes calldata _data) external returns (bool, bytes memory) {
        return _ethAmount == 0 
            ? _executeNoValue(_data[0:65], _data[65:81], _to, _data[81:])
            : _executeWithValue(_data[0:65], _data[65:81], _to, _ethAmount, _data[81:]);
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

    function executeNoValue(address _to, bytes calldata _data) external returns (bool, bytes memory) {
        return _executeNoValue(_data[0:65], _data[65:81], _to, _data[81:]);
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

    function approveThenExecute(address _to, uint256 _ethAmount, address _erc20, address _spender, uint256 _approveAmount, bytes calldata _data) external returns (bool, bytes memory) {
        return _approveThenExecuteWithParams(
            _data[0:65],
            _data[65:81],
            _erc20,
            _spender,
            _approveAmount,
            _to,
            _ethAmount,
            _data[81:]
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
        bytes32 hash;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, APPROVE_THEN_EXECUTE_TYPEHASH)
            let nonceValue := shr(128, calldataload(_nonceBytes.offset))
            mstore(add(ptr, 0x20), nonceValue)
            // erc20 address right-aligned in 32 bytes
            let erc20Raw := calldataload(_erc20Bytes.offset)
            mstore(add(ptr, 0x40), shr(96, erc20Raw))
            // Write spender (20 bytes right-aligned in 32 bytes)
            let spenderRaw := calldataload(_spenderBytes.offset)
            mstore(add(ptr, 0x60), shr(96, spenderRaw))
            // Write approveAmount (32 bytes)
            calldatacopy(add(ptr, 0x80), _approveAmountBytes.offset, 32)
            mstore(add(ptr, 0xa0), _outputContract)
            mstore(add(ptr, 0xc0), _ethAmount)
            // Compute argsHash in assembly
            let argsPtr := add(ptr, 0xe0)
            calldatacopy(argsPtr, _arguments.offset, _arguments.length)
            let argsHash := keccak256(argsPtr, _arguments.length)
            mstore(add(ptr, 0xe0), argsHash)
            // total = 0x100 (256) bytes
            hash := keccak256(ptr, 0x100)
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
            if iszero(call(gas(), token, 0, ptr, 0x44, 0, 0)) {
                // attempt a special case for usdt on eth mainnet usually requires resetting approval to 0 then setting it again
                mstore(ptr, shl(224, 0x095ea7b3)) // IERC20.approve selector
                calldatacopy(add(ptr, 0x10), _spenderBytes.offset, 20)
                mstore(add(ptr, 0x24), 0) // essentially write nothing to the next word in the register so it's 0
                if iszero(call(gas(), token, 0, ptr, 0x44, 0, 0)) {
                    let errorPtr := mload(0x40)
                    mstore(errorPtr, APPROVAL_TO_0_FAILED_SELECTOR)
                    revert(errorPtr, 0x04)
                }
                calldatacopy(add(ptr, 0x24), _approveAmountBytes.offset, 32) // then write something
                if iszero(call(gas(), token, 0, ptr, 0x44, 0, 0)) {
                    let errorPtr := mload(0x40)
                    mstore(errorPtr, APPROVAL_FAILED_SELECTOR)
                    revert(errorPtr, 0x04)
                }
            } // set the approval
        }
        (bool success, bytes memory result) =
            _ethAmount == 0 ? _outputContract.call(_arguments) : _outputContract.call{value: _ethAmount}(_arguments);
        if (success) {
            return (success, result);
        }
        revert ExecutionFailed();
    }

    function _approveThenExecuteWithParams(
        bytes calldata _signature, // 65 bytes
        bytes calldata _nonceBytes, // uint128
        address _erc20,
        address _spender,
        uint256 _approveAmount,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments
    ) internal returns (bool, bytes memory) {
        bytes32 hash;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, APPROVE_THEN_EXECUTE_TYPEHASH)
            let nonceValue := shr(128, calldataload(_nonceBytes.offset))
            mstore(add(ptr, 0x20), nonceValue)
            mstore(add(ptr, 0x40), _erc20)
            mstore(add(ptr, 0x60), _spender)
            mstore(add(ptr, 0x80), _approveAmount)
            mstore(add(ptr, 0xa0), _outputContract)
            mstore(add(ptr, 0xc0), _ethAmount)
            // Compute argsHash in assembly
            let argsPtr := add(ptr, 0xe0)
            calldatacopy(argsPtr, _arguments.offset, _arguments.length)
            let argsHash := keccak256(argsPtr, _arguments.length)
            mstore(add(ptr, 0xe0), argsHash)
            // total = 0x100 (256) bytes
            hash := keccak256(ptr, 0x100)
        }
        hash = _hashTypedData(hash);

        _validateExecute(hash, _signature, _nonceBytes);
        
        // Build calldata for approve(spender, amount) and call token
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, shl(224, 0x095ea7b3)) // IERC20.approve selector
            mstore(add(ptr, 0x04), _spender)
            mstore(add(ptr, 0x24), _approveAmount)
            if iszero(call(gas(), _erc20, 0, ptr, 0x44, 0, 0)) {
                // attempt a special case for usdt on eth mainnet usually requires resetting approval to 0 then setting it again
                mstore(ptr, shl(224, 0x095ea7b3)) // IERC20.approve selector
                mstore(add(ptr, 0x04), _spender)
                mstore(add(ptr, 0x24), 0)
                if iszero(call(gas(), _erc20, 0, ptr, 0x44, 0, 0)) {
                    mstore(0x00, APPROVAL_TO_0_FAILED_SELECTOR)
                    revert(0x00, 0x04)
                }
                mstore(ptr, shl(224, 0x095ea7b3)) // IERC20.approve selector
                mstore(add(ptr, 0x04), _spender)
                mstore(add(ptr, 0x24), _approveAmount)
                if iszero(call(gas(), _erc20, 0, ptr, 0x44, 0, 0)) {
                    mstore(0x00, APPROVAL_FAILED_SELECTOR)
                    revert(0x00, 0x04)
                }
            }
        }

        (bool success, bytes memory result) =
            _ethAmount == 0 ? _outputContract.call(_arguments) : _outputContract.call{value: _ethAmount}(_arguments);
        if (success) {
            return (success, result);
        }
        revert ExecutionFailed();
    }

    function _approveThenExecuteNoReturn(
        bytes calldata _signature, // 65 bytes
        bytes calldata _nonceBytes, // uint128
        bytes calldata _erc20Bytes, // address (20 bytes)
        bytes calldata _spenderBytes, // address (20 bytes)
        bytes calldata _approveAmountBytes, // uint256 (32 bytes)
        bytes calldata _outputContractBytes, // address (20 bytes)
        bytes calldata _ethAmountBytes,
        bytes calldata _arguments
    ) internal {
        bytes32 hash;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, APPROVE_THEN_EXECUTE_TYPEHASH)
            let nonceValue := shr(128, calldataload(_nonceBytes.offset))
            mstore(add(ptr, 0x20), nonceValue)
            // erc20 address right-aligned in 32 bytes
            let erc20Raw := calldataload(_erc20Bytes.offset)
            mstore(add(ptr, 0x40), shr(96, erc20Raw))
            // spender address right-aligned in 32 bytes
            let spenderRaw := calldataload(_spenderBytes.offset)
            mstore(add(ptr, 0x60), shr(96, spenderRaw))
            // approve amount (32 bytes)
            calldatacopy(add(ptr, 0x80), _approveAmountBytes.offset, 32)
            // output contract right-aligned
            let outRaw := calldataload(_outputContractBytes.offset)
            mstore(add(ptr, 0xa0), shr(96, outRaw))
            // eth amount (right-align arbitrary length up to 32 bytes)
            {
                let rawEth := calldataload(_ethAmountBytes.offset)
                let shiftBits := mul(sub(32, _ethAmountBytes.length), 8)
                let ethVal := shr(shiftBits, rawEth)
                mstore(add(ptr, 0xc0), ethVal)
            }
            // args hash
            let argsPtr := add(ptr, 0xe0)
            calldatacopy(argsPtr, _arguments.offset, _arguments.length)
            let argsHash := keccak256(argsPtr, _arguments.length)
            mstore(add(ptr, 0xe0), argsHash)
            hash := keccak256(ptr, 0x100)
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
            if iszero(call(gas(), token, 0, ptr, 0x44, 0, 0)) {
                // attempt a special case for usdt on eth mainnet usually requires resetting approval to 0 then setting it again
                mstore(ptr, shl(224, 0x095ea7b3)) // IERC20.approve selector
                calldatacopy(add(ptr, 0x10), _spenderBytes.offset, 20)
                mstore(add(ptr, 0x24), 0) // essentially write nothing to the next word in the register so it's 0
                if iszero(call(gas(), token, 0, ptr, 0x44, 0, 0)) {
                    let errorPtr := mload(0x40)
                    mstore(errorPtr, APPROVAL_TO_0_FAILED_SELECTOR)
                    revert(errorPtr, 0x04)
                }
                calldatacopy(add(ptr, 0x24), _approveAmountBytes.offset, 32) // then write something
                if iszero(call(gas(), token, 0, ptr, 0x44, 0, 0)) {
                    let errorPtr := mload(0x40)
                    mstore(errorPtr, APPROVAL_FAILED_SELECTOR)
                    revert(errorPtr, 0x04)
                }
            } // set the approval
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
        bytes calldata _outputContractBytes,
        bytes calldata _arguments
    ) internal {
        bytes32 hash;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, EXECUTION_TYPEHASH)
            let nonceValue := shr(128, calldataload(_nonceBytes.offset))
            mstore(add(ptr, 0x20), nonceValue)
            let raw := calldataload(_outputContractBytes.offset)
            mstore(add(ptr, 0x40), shr(96, raw))
            mstore(add(ptr, 0x60), 0)
            // Compute argsHash in assembly to avoid a separate solidity temp
            let argsPtr := add(ptr, 0x80)
            calldatacopy(argsPtr, _arguments.offset, _arguments.length)
            let argsHash := keccak256(argsPtr, _arguments.length)
            mstore(add(ptr, 0x80), argsHash)
            hash := keccak256(ptr, 0xa0)
        }
        hash = _hashTypedData(hash);

        _validateExecute(hash, _signature, _nonceBytes);

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
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, EXECUTION_TYPEHASH)
            let nonceValue := shr(128, calldataload(_nonceBytes.offset))
            mstore(add(ptr, 0x20), nonceValue)
            mstore(add(ptr, 0x40), _outputContract)
            mstore(add(ptr, 0x60), 0) // ethAmount = 0
            // Compute argsHash in assembly
            let argsPtr := add(ptr, 0x80)
            calldatacopy(argsPtr, _arguments.offset, _arguments.length)
            let argsHash := keccak256(argsPtr, _arguments.length)
            mstore(add(ptr, 0x80), argsHash)
            hash := keccak256(ptr, 0xa0)
        }
        hash = _hashTypedData(hash);

        _validateExecute(hash, _signature, _nonceBytes);
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
        bytes32 hash; // all this assembly to avoid using abi.encode
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, EXECUTION_TYPEHASH)
            let nonceValue := shr(128, calldataload(_nonceBytes.offset))
            mstore(add(ptr, 0x20), nonceValue)
            mstore(add(ptr, 0x40), _outputContract)
            mstore(add(ptr, 0x60), _ethAmount)
            // Compute argsHash in assembly
            let argsPtr := add(ptr, 0x80)
            calldatacopy(argsPtr, _arguments.offset, _arguments.length)
            let argsHash := keccak256(argsPtr, _arguments.length)
            mstore(add(ptr, 0x80), argsHash)
            hash := keccak256(ptr, 0xa0)
        }
        hash = _hashTypedData(hash);

        _validateExecute(hash, _signature, _nonceBytes);
        (bool success, bytes memory result) = _outputContract.call{value: _ethAmount}(_arguments);
        if (success) {
            return (success, result);
        }
        revert ExecutionFailed();
    }

    function _executeWithValueNoReturn(
        bytes calldata _signature,
        bytes calldata _nonceBytes,
        bytes calldata _outputContractBytes,
        uint256 _ethAmount,
        bytes calldata _arguments
    ) internal {
        bytes32 argsHash = keccak256(_arguments);
        bytes32 hash; // all this assembly to avoid using abi.encode
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, EXECUTION_TYPEHASH)
            let nonceValue := shr(128, calldataload(_nonceBytes.offset))
            mstore(add(ptr, 0x20), nonceValue)
            let raw := calldataload(_outputContractBytes.offset)
            mstore(add(ptr, 0x40), shr(96, raw))
            mstore(add(ptr, 0x60), _ethAmount)
            mstore(add(ptr, 0x80), argsHash)
            hash := keccak256(ptr, 0xa0)
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
            return (success, result);
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

    function _executeBatchSession(
        bytes calldata _signature,
        bytes calldata _counterBytes,
        bytes calldata _deadlineBytes,
        address _outputContract,
        IBatchExecution.Call[] calldata _calls
    ) internal returns (bool, bytes[] memory) {
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

    function _executeSessionArbitraryNoReturn(
        bytes calldata _signature,
        bytes calldata _counterBytes,
        bytes calldata _deadlineBytes,
        bytes calldata _outputContractBytes,
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
            if iszero(call(gas(), outputContract, 0, ptr, _arguments.length, 0, 0)) { revert(0, 0) }
        }
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
            return (success, result);
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

    function _executeBatchSessionArbitrary(
        bytes calldata _signature,
        bytes calldata _counterBytes,
        bytes calldata _deadlineBytes, // Changed from uint128
        IBatchExecution.Call[] calldata _calls
    ) internal returns (bool, bytes[] memory) {
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

        return (true, results);
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

    function executeSession(bytes calldata data) external returns (bool, bytes memory) {
        // Layout: [signature(65)][counter(16)][deadline(4)][output(20)][ethAmount(32)][args]
        address output;
        uint256 ethAmount;
        assembly {
            output := shr(96, calldataload(add(data.offset, 85)))
            ethAmount := calldataload(add(data.offset, 105))
        }
        return _executeSessionWithValue(data[0:65], data[65:81], data[81:85], output, ethAmount, data[137:]);
    }

    function executeSession(address _to, uint256 _ethAmount, bytes calldata _data) external returns (bool, bytes memory) {
        return _executeSessionWithValue(_data[0:65], _data[65:81], _data[81:85], _to, _ethAmount, _data[85:]);
    }

    function executeBatchSession(bytes calldata data) external returns (bool, bytes[] memory) {
        // Layout: [signature(65)][counter(16)][deadline(4)][output(20)][abi.encode(IBatchExecution.Call[])]
        IBatchExecution.Call[] calldata calls;
        address output;
        assembly {
            output := shr(96, calldataload(add(data.offset, 85)))

            // ABI: at offset 105, we have the head for the dynamic array: [offset=0x20][length][elements]
            calls.offset := add(data.offset, add(105, 0x40))
            calls.length := calldataload(add(data.offset, add(105, 0x20)))
        }
        return _executeBatchSession(data[0:65], data[65:81], data[81:85], output, calls);
    }

    function executeBatchSession(IBatchExecution.Call[] calldata _calls, bytes calldata _data) external returns (bool, bytes[] memory) {
        address output;
        assembly {
            output := shr(96, calldataload(add(_data.offset, 85)))
        }
        return _executeBatchSession(_data[0:65], _data[65:81], _data[81:85], output, _calls);
    }

    function executeSessionArbitrary(bytes calldata data) external returns (bool, bytes memory) {
        // does not limit output contract
        // Layout: [signature(65)][counter(16)][deadline(4)][output(20)][ethAmount(32)][args]
        address output;
        uint256 ethAmount;
        assembly {
            output := shr(96, calldataload(add(data.offset, 85)))
            ethAmount := calldataload(add(data.offset, 105))
        }
        return _executeSessionArbitraryWithValue(data[0:65], data[65:81], data[81:85], output, ethAmount, data[137:]);
    }

    function executeSessionArbitrary(address _to, uint256 _ethAmount, bytes calldata _data) external returns (bool, bytes memory) {
        return _executeSessionArbitraryWithValue(_data[0:65], _data[65:81], _data[81:85], _to, _ethAmount, _data[85:]);
    }

    function executeBatchSessionArbitrary(bytes calldata data) external returns (bool, bytes[] memory) {
        // Layout: [signature(65)][counter(16)][deadline(4)][abi.encode(IBatchExecution.Call[])]
        IBatchExecution.Call[] calldata calls;
        assembly {
            // ABI: at offset 85, we have the head for the dynamic array: [offset=0x20][length][elements]
            calls.offset := add(data.offset, add(85, 0x40))
            calls.length := calldataload(add(data.offset, add(85, 0x20)))
        }
        // For arbitrary batch, sender is implicitly msg.sender in typehash, keep as paymaster (msg.sender)
        return _executeBatchSessionArbitrary(data[0:65], data[65:81], data[81:85], calls);
    }

    function executeBatchSessionArbitrary(IBatchExecution.Call[] calldata _calls, bytes calldata _data) external returns (bool, bytes[] memory) {
        return _executeBatchSessionArbitrary(_data[0:65], _data[65:81], _data[81:85], _calls);
    }

    function executeBatch(bytes calldata data) external returns (bool, bytes[] memory) {
        // Layout: [signature(65)][nonce(16)][abi.encode(IBatchExecution.Call[])]
        return _executeBatch(data[0:65], data[65:81], data[81:]);
    }

    function executeBatch(IBatchExecution.Call[] calldata _calls, bytes calldata _data) external returns (bool, bytes[] memory) {
        return _executeBatchWithCalls(_data[0:65], _data[65:81], _calls);
    }

    function _executeBatchWithCalls(bytes calldata _signature, bytes calldata _nonceBytes, IBatchExecution.Call[] calldata _calls)
        internal
        returns (bool, bytes[] memory)
    {
        // Hash the calls array to match the calldata version exactly
        // The calldata version uses keccak256(_calls) where _calls is abi.encode(IBatchExecution.Call[])
        // So we need to hash the encoded calls array
        bytes32 executionsHash = keccak256(abi.encode(_calls));
        bytes32 hash;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, BATCH_EXECUTION_TYPEHASH)
            let nonceValue := shr(128, calldataload(_nonceBytes.offset))
            mstore(add(ptr, 0x20), nonceValue)
            mstore(add(ptr, 0x40), executionsHash)
            hash := keccak256(ptr, 0x60)
            mstore(0x40, add(ptr, 0x60)) // Update free memory pointer
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
        return (true, results);
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
            let nonceValue := shr(128, calldataload(_nonceBytes.offset))
            mstore(add(ptr, 0x20), nonceValue)
            mstore(add(ptr, 0x40), executionsHash)
            hash := keccak256(ptr, 0x60)
            mstore(0x40, add(ptr, 0x60)) // Update free memory pointer
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
        return (true, results);
    }

    function _executeBatchNoReturn(bytes calldata _signature, bytes calldata _nonceBytes, bytes calldata _calls)
        internal
    {
        bytes32 executionsHash = keccak256(_calls);
        bytes32 hash;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, BATCH_EXECUTION_TYPEHASH)
            let nonceValue := shr(128, calldataload(_nonceBytes.offset))
            mstore(add(ptr, 0x20), nonceValue)
            mstore(add(ptr, 0x40), executionsHash)
            hash := keccak256(ptr, 0x60)
            mstore(0x40, add(ptr, 0x60))
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

    function hashApproveThenExecute(
        uint128 _nonce,
        address _erc20Contract,
        address _spender,
        uint256 _approveAmount,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments
    ) external view returns (bytes32) {
        bytes32 hash;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, APPROVE_THEN_EXECUTE_TYPEHASH)
            // Store nonce as 32-byte value (same as internal function)
            mstore(add(ptr, 0x20), _nonce)
            mstore(add(ptr, 0x40), _erc20Contract)
            mstore(add(ptr, 0x60), _spender)
            mstore(add(ptr, 0x80), _approveAmount)
            mstore(add(ptr, 0xa0), _outputContract)
            mstore(add(ptr, 0xc0), _ethAmount)
            // Compute argsHash in assembly
            let argsPtr := add(ptr, 0xe0)
            calldatacopy(argsPtr, _arguments.offset, _arguments.length)
            let argsHash := keccak256(argsPtr, _arguments.length)
            mstore(add(ptr, 0xe0), argsHash)
            // total = 0x100 (256) bytes
            hash := keccak256(ptr, 0x100)
            mstore(0x40, add(ptr, 0x100)) // Update free memory pointer
        }
        return _hashTypedData(hash);
    }

    function hashSessionExecution(uint128 _counter, uint32 _deadline, address _sender, address _outputContract)
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
