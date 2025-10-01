// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ITKGasDelegate} from "./interfaces/ITKGasDelegate.sol";
import {IBatchExecution} from "./interfaces/IBatchExecution.sol";

contract TKGasStation {
    error NotDelegated();

    address public immutable tkGasDelegate;

    constructor(address _tkGasDelegate) {
        tkGasDelegate = _tkGasDelegate;
    }

    fallback(bytes calldata) external returns (bytes memory) {
        // Parse bytes 1-20 as the address to call as a gas delegate
        address targetDelegate;
        assembly {
            targetDelegate := shr(96, calldataload(1))
        }

        // Check if the target delegate is a valid gas delegate
        if (!_isDelegated(targetDelegate)) {
            revert NotDelegated();
        }

        // Send the remaining calldata (bytes 21+) to the target delegate
        (bool success, bytes memory data) = targetDelegate.call(msg.data[21:]);
        if (!success) {
            assembly {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }
        }
        return data;
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

    function isDelegated(address _targetEoA) external view returns (bool) {
        return _isDelegated(_targetEoA);
    }

    function execute(
        address _targetEoA,
        bytes calldata _signature,
        uint128 _nonce,
        address _outputContract,
        bytes calldata _arguments
    ) external returns (bool, bytes memory) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(payable(_targetEoA)).execute(_signature, _nonce, _outputContract, _arguments);
    }

    function execute(
        address _targetEoA,
        bytes calldata _signature,
        uint128 _nonce,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments
    ) external returns (bool, bytes memory) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(payable(_targetEoA)).execute(_signature, _nonce, _outputContract, _ethAmount, _arguments);
    }

    function executeSession(
        address _targetEoA,
        bytes calldata _signature,
        uint128 _counter,
        uint128 _deadline,
        address _outputContract,
        bytes calldata _arguments
    ) external returns (bool, bytes memory) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(payable(_targetEoA)).executeSession(
            _signature, _counter, _deadline, _outputContract, _arguments
        );
    }

    function executeSession(
        address _targetEoA,
        bytes calldata _signature,
        uint128 _counter,
        uint128 _deadline,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments
    ) external returns (bool, bytes memory) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(payable(_targetEoA)).executeSession(
            _signature, _counter, _deadline, _outputContract, _ethAmount, _arguments
        );
    }

    function executeBatchSession(
        address _targetEoA,
        bytes calldata _signature,
        uint128 _counter,
        uint128 _deadline,
        address _sender,
        IBatchExecution.Call[] calldata _calls
    ) external returns (bool, bytes[] memory) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(payable(_targetEoA)).executeBatchSession(_signature, _counter, _deadline, _sender, _calls);
    }

    function executeSessionArbitrary(
        address _targetEoA,
        bytes calldata _signature,
        uint128 _counter,
        uint128 _deadline,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments
    ) external returns (bool, bytes memory) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(payable(_targetEoA)).executeSessionArbitrary(
            _signature, _counter, _deadline, _outputContract, _ethAmount, _arguments
        );
    }

    function executeSessionArbitrary(
        address _targetEoA,
        bytes calldata _signature,
        uint128 _counter,
        uint128 _deadline,
        address _outputContract,
        bytes calldata _arguments
    ) external returns (bool, bytes memory) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(payable(_targetEoA)).executeSessionArbitrary(
            _signature, _counter, _deadline, _outputContract, _arguments
        );
    }

    function executeBatchSessionArbitrary(
        address _targetEoA,
        bytes calldata _signature,
        uint128 _counter,
        uint128 _deadline,
        IBatchExecution.Call[] calldata _calls
    ) external returns (bool, bytes[] memory) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(payable(_targetEoA)).executeBatchSessionArbitrary(_signature, _counter, _deadline, _calls);
    }

    function executeBatch(
        address _targetEoA,
        bytes calldata _signature,
        uint128 _nonce,
        IBatchExecution.Call[] calldata _calls
    ) external returns (bool, bytes[] memory) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(payable(_targetEoA)).executeBatch(_signature, _nonce, _calls);
    }

    function burnNonce(address _targetEoA, bytes calldata _signature, uint128 _nonce) external {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        ITKGasDelegate(payable(_targetEoA)).burnNonce(_signature, _nonce);
    }

    function burnSessionCounter(address _targetEoA, bytes calldata _signature, uint128 _counter, address _sender)
        external
    {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        ITKGasDelegate(payable(_targetEoA)).burnSessionCounter(_signature, _counter, _sender);
    }

    /* Lense Functions */

    function getNonce(address _targetEoA) external view returns (uint128) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(payable(_targetEoA)).nonce();
    }

    function getSessionCounter(address _targetEoA) external view returns (uint128) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(payable(_targetEoA)).sessionCounter();
    }
}
