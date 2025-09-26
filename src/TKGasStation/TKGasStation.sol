// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ITKGasDelegate} from "./ITKGasDelegate.sol";
import {IBatchExecution} from "./IBatchExecution.sol";

contract TKGasStation {
    error NotDelegated();

    address public immutable tkGasDelegate;

    constructor(address _tkGasDelegate) {
        tkGasDelegate = _tkGasDelegate;
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

    function execute(address _targetEoA, uint128 _nonce, address _outputContract, bytes calldata _arguments, bytes calldata _signature) external returns (bool, bytes memory) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(payable(_targetEoA)).execute(_nonce, _outputContract, _arguments, _signature);
    }

    function execute(address _targetEoA, uint128 _nonce, address _outputContract, uint256 _ethAmount, bytes calldata _arguments, bytes calldata _signature) external returns (bool, bytes memory) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(payable(_targetEoA)).execute(_nonce, _outputContract, _ethAmount, _arguments, _signature);
    }

    function executeTimeboxed(address _targetEoA, uint128 _counter, uint128 _deadline, address _outputContract, bytes calldata _arguments, bytes calldata _signature) external returns (bool, bytes memory) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(payable(_targetEoA)).executeTimeboxed(_counter, _deadline, _outputContract, _arguments, _signature);
    }

    function executeTimeboxed(address _targetEoA, uint128 _counter, uint128 _deadline, address _outputContract, uint256 _ethAmount, bytes calldata _arguments, bytes calldata _signature) external returns (bool, bytes memory) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(payable(_targetEoA)).executeTimeboxed(_counter, _deadline, _outputContract, _ethAmount, _arguments, _signature);
    }

    function executeBatchTimeboxed(address _targetEoA, uint128 _counter, uint128 _deadline, address _sender, IBatchExecution.Execution[] calldata _executions, bytes calldata _signature) external returns (bool, bytes[] memory) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(payable(_targetEoA)).executeBatchTimeboxed(_counter, _deadline, _sender, _executions, _signature);
    }

    function executeTimeboxedArbitrary(address _targetEoA, uint128 _counter, uint128 _deadline, address _outputContract, uint256 _ethAmount, bytes calldata _arguments, bytes calldata _signature) external returns (bool, bytes memory) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(payable(_targetEoA)).executeTimeboxedArbitrary(_counter, _deadline, _outputContract, _ethAmount, _arguments, _signature);
    }

    function executeTimeboxedArbitrary(address _targetEoA, uint128 _counter, uint128 _deadline, address _outputContract, bytes calldata _arguments, bytes calldata _signature) external returns (bool, bytes memory) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(payable(_targetEoA)).executeTimeboxedArbitrary(_counter, _deadline, _outputContract, _arguments, _signature);
    }

    function executeBatchTimeboxedArbitrary(address _targetEoA, uint128 _counter, uint128 _deadline, IBatchExecution.Execution[] calldata _executions, bytes calldata _signature) external returns (bool, bytes[] memory) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(payable(_targetEoA)).executeBatchTimeboxedArbitrary(_counter, _deadline, _executions, _signature);
    }

    function executeBatch(address _targetEoA, uint128 _nonce, IBatchExecution.Execution[] calldata _executions, bytes calldata _signature) external returns (bool, bytes[] memory) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(payable(_targetEoA)).executeBatch(_nonce, _executions, _signature);
    }

    function burnNonce(address _targetEoA, uint128 _nonce, bytes calldata _signature) external {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        ITKGasDelegate(payable(_targetEoA)).burnNonce(_nonce, _signature);
    }

    function burnTimeboxedCounter(address _targetEoA, uint128 _counter, address _sender, bytes calldata _signature) external {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        ITKGasDelegate(payable(_targetEoA)).burnTimeboxedCounter(_counter, _sender, _signature);
    }

    /* Lense Functions */ 

    function getNonce(address _targetEoA) external view returns (uint128) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(payable(_targetEoA)).nonce();
    }

    function getTimeboxedCounter(address _targetEoA) external view returns (uint128) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(payable(_targetEoA)).timeboxedCounter();
    }
}