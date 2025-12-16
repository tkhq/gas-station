// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {TKGasStation} from "../TKGasStation.sol";

import {TransientSignature} from "../structs/TransientSignature.sol";
import {ITKGasDelegate} from "../interfaces/ITKGasDelegate.sol";
import {ITKSmartWalletFactory} from "../interfaces/ITKSmartWalletFactory.sol";
import {IsDelegated} from "./IsDelegated.sol";


contract TKSmartWalletGasStation is TKGasStation {
    // Recommended values for Solady's LibClone minimal proxy pattern
    uint256 private constant EXPECTED_RUNTIME_CODE_SIZE = 0x2c; // 44 bytes
    bytes11 private constant EXPECTED_PREFIX = 0x3d3d3d3d363d3d37363d73;
    bytes13 private constant EXPECTED_SUFFIX = 0x5af43d3d93803e602a57fd5bf3;

    ITKSmartWalletFactory public immutable FACTORY;

    constructor(address _factoryAddress) TKGasStation(ITKSmartWalletFactory(_factoryAddress).IMPLEMENTATION()) {
        FACTORY = ITKSmartWalletFactory(_factoryAddress);
    }
    
    function _isDelegated(address _targetEoA) internal override view returns (bool) {
        return IsDelegated.isDelegatedMinimalProxy(
            _targetEoA,
            TK_GAS_DELEGATE,
            EXPECTED_RUNTIME_CODE_SIZE,
            EXPECTED_PREFIX,
            EXPECTED_SUFFIX
        );
    }

    function executeMultiSig(TransientSignature[] calldata _signatures, address _target, address _to, uint256 _ethAmount, bytes calldata _data) external {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        ITKSmartWalletFactory(FACTORY).setTransientSignatures(_target, _signatures);
        ITKGasDelegate(_target).execute(_to, _ethAmount, _data);
    }

}

