// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ITKSmartWalletManager} from "./Interfaces/ITKSmartWalletManager.sol";
import {ITKSmartWallet} from "./Interfaces/ITKSmartWallet.sol";

contract ManagedTKSmartWallet is ITKSmartWallet {
    address public immutable manager;

    error ZeroAddress();
    error ValidationFailed();
    error ExecutionFailed();

    constructor(address _manager) {
        if (_manager == address(0)) {
            revert ZeroAddress();
        }
        manager = _manager;
    }

    function getNonce() external view override returns (uint256) {
        return ITKSmartWalletManager(manager).getNonce(address(this));
    }

    function login(address _executor, uint64 _timeout) external override {
        ITKSmartWalletManager(manager).login(_executor, _timeout);
    }

    function logout() external override {
        ITKSmartWalletManager(manager).logout();
    }

    function executeMetaTx(
        address _executor,
        uint256 _nonce,
        uint256 _timeout,
        uint256 _ethAmount,
        bytes calldata _executionData,
        bytes calldata _signature
    ) external override returns (bool success, bytes memory result) {
        (bool valid, address target) = ITKSmartWalletManager(manager).validateAllReturnInteractionContract(
            _executor,
            _nonce,
            _timeout,
            _ethAmount,
            _executionData,
            _signature
        );
        if (!valid || target == address(0)) {
            revert ValidationFailed();
        }
        (success, result) = target.call{value: _ethAmount}(_executionData);
        if (!success) {
            revert ExecutionFailed();
        }
    }

    function execute(uint256 _ethAmount, bytes calldata _executionData) external override returns (bool success, bytes memory result) {
        (bool valid, address target) = ITKSmartWalletManager(manager).validateExecutionDataOnlyReturnInteractionContract(_ethAmount, _executionData);
        if (!valid || target == address(0)) {
            revert ValidationFailed();
        }
        (success, result) = target.call{value: _ethAmount}(_executionData);
        if (!success) {
            revert ExecutionFailed();
        }
    }

    receive() external payable {}
} 