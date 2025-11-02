// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ITKGasDelegate} from "./interfaces/ITKGasDelegate.sol";
import {ITKGasStation} from "./interfaces/ITKGasStation.sol";
import {IBatchExecution} from "./interfaces/IBatchExecution.sol";

contract TKGasStation is ITKGasStation {
    error NotDelegated();
    error NoEthAllowed();
    error InvalidFunctionSelector();
    error ExecutionFailed();

    address public immutable tkGasDelegate;

    constructor(address _tkGasDelegate) {
        tkGasDelegate = _tkGasDelegate;
    }

    receive() external payable {
        revert NoEthAllowed();
    }

    fallback(bytes calldata data) external returns (bytes memory) {
        address target;
        assembly {
            target := shr(96, calldataload(add(data.offset, 1)))
        }
        if (!_isDelegated(target)) {
            revert NotDelegated();
        }

        if(bytes1(data[21]) == 0x00) { // check if the first byte is 0x00

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

        return delegatedTo == tkGasDelegate;
    }

    // Execute functions
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

    function execute(address _target, address _to, uint256 _ethAmount, bytes calldata _data) external {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        ITKGasDelegate(_target).execute(_to, _ethAmount, _data);
    }

    // ApproveThenExecute functions
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

    function executeBatch(address _target, IBatchExecution.Call[] calldata _calls, bytes calldata _data) external {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        ITKGasDelegate(_target).executeBatch(_calls, _data);
    }

    function burnNonce(address _targetEoA, bytes calldata _signature, uint128 _nonce) external {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        ITKGasDelegate(_targetEoA).burnNonce(_signature, _nonce);
    }

    /* Lense Functions */

    function getNonce(address _targetEoA) external view returns (uint128) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        uint128 nonce = ITKGasDelegate(_targetEoA).nonce();
        return nonce;
    }

    function isDelegated(address _targetEoA) external view returns (bool) {
        return _isDelegated(_targetEoA);
    }

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

    function hashBurnNonce(address _targetEoA, uint128 _nonce) external view returns (bytes32) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(_targetEoA).hashBurnNonce(_nonce);
    }

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

    function hashBurnSessionCounter(address _targetEoA, uint128 _counter)
        external
        view
        returns (bytes32)
    {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(_targetEoA).hashBurnSessionCounter(_counter);
    }

}
