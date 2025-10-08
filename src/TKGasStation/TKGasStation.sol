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

        bytes1 functionSelector = bytes1(data[22] & 0xf0);  // mask the last nibble 

        // only allow execute functions, no session functions 
        if (functionSelector == 0x00 || functionSelector == 0x10 || functionSelector == 0x20 || functionSelector == 0x30) { 
            (bool success, bytes memory result) = target.call(data[21:]);
            if (success) {
                return result;
            }
            revert ExecutionFailed();
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

    function execute(address _target, bytes calldata data) external returns (bool, bytes memory) {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(_target).execute(data);
    }

    function execute(address _target, address _to, uint256 _ethAmount, bytes calldata _data) external returns (bool, bytes memory) {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(_target).execute(_to, _ethAmount, _data);
    }

    function executeNoValue(address _target, bytes calldata data) external returns (bool, bytes memory) {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(_target).executeNoValue(data);
    }

    function executeNoValue(address _target, address _to, bytes calldata _data) external returns (bool, bytes memory) {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(_target).executeNoValue(_to, _data);
    }


    function approveThenExecute(address _target, bytes calldata data) external returns (bool, bytes memory) {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(_target).approveThenExecute(data);
    }


    function approveThenExecute(address _target, address _to, uint256 _ethAmount, address _erc20, address _spender, uint256 _approveAmount, bytes calldata _data) external returns (bool, bytes memory) {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(_target).approveThenExecute(_to, _ethAmount, _erc20, _spender, _approveAmount, _data);
    }

    function executeSession(address _target, bytes calldata data) external returns (bool, bytes memory) {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(_target).executeSession(data);
    }

    function executeSession(address _target, address _to, uint256 _ethAmount, bytes calldata _data) external returns (bool, bytes memory) {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(_target).executeSession(_to, _ethAmount, _data);
    }

    function executeBatch(address _target, bytes calldata data) external returns (bool, bytes[] memory) {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(_target).executeBatch(data);
    }

    function executeBatch(address _target, IBatchExecution.Call[] calldata _calls, bytes calldata _data) external returns (bool, bytes[] memory) {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(_target).executeBatch(_calls, _data);
    }

    function executeBatchSession(address _target, bytes calldata data) external returns (bool, bytes[] memory) {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(_target).executeBatchSession(data);
    }

    function executeBatchSession(address _target, IBatchExecution.Call[] calldata _calls, bytes calldata _data) external returns (bool, bytes[] memory) {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(_target).executeBatchSession(_calls, _data);
    }

    function executeSessionArbitrary(address _target, bytes calldata data) external returns (bool, bytes memory) {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(_target).executeSessionArbitrary(data);
    }

    function executeSessionArbitrary(address _target, address _to, uint256 _ethAmount, bytes calldata _data) external returns (bool, bytes memory) {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(_target).executeSessionArbitrary(_to, _ethAmount, _data);
    }

    function executeBatchSessionArbitrary(address _target, bytes calldata data) external returns (bool, bytes[] memory) {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(_target).executeBatchSessionArbitrary(data);
    }

    function executeBatchSessionArbitrary(address _target, IBatchExecution.Call[] calldata _calls, bytes calldata _data) external returns (bool, bytes[] memory) {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(_target).executeBatchSessionArbitrary(_calls, _data);
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
        (, uint128 nonce) = ITKGasDelegate(_targetEoA).state();
        return nonce;
    }

    function isDelegated(address _targetEoA) external view returns (bool) {
        return _isDelegated(_targetEoA);
    }
}
