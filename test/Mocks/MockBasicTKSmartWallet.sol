// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {BasicTKSmartWallet} from "../../src/BasicTKSmartWallet.sol";

contract MockBasicTKSmartWallet is BasicTKSmartWallet {
    constructor(address _interactionContract, bool _useManager, bytes4[] memory _allowedFunctions) BasicTKSmartWallet(_interactionContract, _useManager, _allowedFunctions) {}

    function isAllowedFunctionExternal(bytes4 _functionId) external view {
        _isAllowedFunction(_functionId);
    }
    
    function validateExecutorExternal(address _executor) external view {
        _validateExecutor(_executor);
    }
    
    function getHash(address _executor, uint256 _nonce, uint256 _timeout, uint256 _ethAmount, bytes memory _executionData) external view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(TK_SMART_WALLET_EXECUTE_TYPEHASH, _executor, _nonce, _timeout, _ethAmount, _executionData)));
    }
    
}