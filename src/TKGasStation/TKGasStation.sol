// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ITKGasDelegate} from "./interfaces/ITKGasDelegate.sol";

contract TKGasStation {
    error NotDelegated();
    error NoEthAllowed();
    error InvalidFunctionSelector();

    address public immutable tkGasDelegate;

    constructor(address _tkGasDelegate) {
        tkGasDelegate = _tkGasDelegate;
    }

    receive() external payable {
        revert NoEthAllowed();
    }
/*
    fallback(bytes calldata data) external returns (bytes memory) {
        address target;
        assembly {
            target := shr(96, calldataload(add(data.offset, 1)))
            value := calldataload(add(data.offset, 1))
        }
        if (!_isDelegated(target)) {
            revert NotDelegated();
        }

        bytes1 functionSelector = bytes1(data[22] & 0xf0);

        if (functionSelector == 0x00 || functionSelector == 0x10 || functionSelector == 0x20 || functionSelector == 0x30) { 
            return target.call(data[21:]);
        }

        revert InvalidFunctionSelector();
    }
    */ 

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

    function execute(address _targetEoA, bytes calldata _data) external returns (bool, bytes memory) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(payable(_targetEoA)).execute(_data);
    }

    function execute(address _targetEoA, address _to, uint256 ethAmount, bytes calldata _data) external returns (bool, bytes memory) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(payable(_targetEoA)).execute(_to, ethAmount, _data);
    }

    function executeNoValue(address _targetEoA, bytes calldata _data) external returns (bool, bytes memory) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(payable(_targetEoA)).executeNoValue(_data);
    }

    function approveThenExecute(address _targetEoA, bytes calldata _data) external returns (bool, bytes memory) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(payable(_targetEoA)).approveThenExecute(_data);
    }

    function executeBatch(address _targetEoA, bytes calldata _data) external returns (bool, bytes[] memory) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(payable(_targetEoA)).executeBatch(_data);
    }

    function burnNonce(address _targetEoA, bytes calldata _signature, uint128 _nonce) external {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        ITKGasDelegate(payable(_targetEoA)).burnNonce(_signature, _nonce);
    }

    /* Lense Functions */

    function getNonce(address _targetEoA) external view returns (uint128) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        (, uint128 nonce) = ITKGasDelegate(payable(_targetEoA)).state();
        return nonce;
    }

    function isDelegated(address _targetEoA) external view returns (bool) {
        return _isDelegated(_targetEoA);
    }
}
