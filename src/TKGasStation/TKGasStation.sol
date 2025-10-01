// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ITKGasDelegate} from "./interfaces/ITKGasDelegate.sol";

contract TKGasStation {
    error NotDelegated();
    error NoEthAllowed();

    address public immutable tkGasDelegate;

    constructor(address _tkGasDelegate) {
        tkGasDelegate = _tkGasDelegate;
    }

    receive() external payable {
        revert NoEthAllowed();
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

    function execute(address _targetEoA, bytes calldata _data) external returns (bool, bytes memory) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(payable(_targetEoA)).execute(_data);
    }

    function executeNoValue(address _targetEoA, bytes calldata _data) external returns (bool, bytes memory) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        return ITKGasDelegate(payable(_targetEoA)).executeNoValue(_data);
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
