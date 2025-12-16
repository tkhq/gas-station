// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {TKGasStation} from "../TKGasStation.sol";

import {TransientSignature} from "../structs/TransientSignature.sol";
import {ITKGasDelegate} from "../interfaces/ITKGasDelegate.sol";
import {ITKSmartWalletFactory} from "../interfaces/ITKSmartWalletFactory.sol";


contract TKSmartWalletGasStation is TKGasStation {

    uint256 public constant EXPECTED_RUNTIME_CODE_SIZE = 0x2c; // 44 bytes
    bytes11 public constant EXPECTED_PREFIX = 0x3d3d3d3d363d3d37363d73;
    bytes13 public constant EXPECTED_SUFFIX = 0x5af43d3d93803e602a57fd5bf3;

    ITKSmartWalletFactory public immutable FACTORY;

    constructor(address _factoryAddress) TKGasStation(ITKSmartWalletFactory(_factoryAddress).IMPLEMENTATION()) {
        FACTORY = ITKSmartWalletFactory(_factoryAddress);
    }
    function _isDelegated(address _targetEoA) internal override view returns (bool) {
        bytes11 codePrefix;
        address delegatedTo;
        bytes13 codeSuffix;

        assembly {
            // Get code size
            let size := extcodesize(_targetEoA)
            
            // Check runtime length matches LibClone minimal proxy (44 bytes / 0x2c)
            // If size doesn't match, set values to zero which will fail the final check
            if eq(size, EXPECTED_RUNTIME_CODE_SIZE) {
                // Allocate memory for code (free memory pointer)
                let codePtr := mload(0x40)
                
                // Copy runtime code to memory
                extcodecopy(_targetEoA, codePtr, 0, size)
                
                // Extract prefix (first 11 bytes)
                codePrefix := mload(codePtr)
                
                // Extract delegated address (bytes 11-30, 20 bytes)
                delegatedTo := shr(96, mload(add(codePtr, 11)))
                
                // Extract suffix (last 13 bytes, starting at byte 31)
                codeSuffix := mload(add(codePtr, 31))
            }
        }
        
        return codePrefix == EXPECTED_PREFIX && delegatedTo == TK_GAS_DELEGATE && codeSuffix == EXPECTED_SUFFIX;
    }

    function executeMultiSig(TransientSignature[] calldata _signatures, address _target, address _to, uint256 _ethAmount, bytes calldata _data) external {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        ITKSmartWalletFactory(FACTORY).setTransientSignatures(_target, _signatures);
        ITKGasDelegate(_target).execute(_to, _ethAmount, _data);
    }

}

