// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

interface ITKSmartWalletManager {
    function validateAllReturnInteractionContract(address _executor, uint256 _nonce, uint256 _timeout, uint256 _ethAmount, bytes calldata _executionData, bytes calldata _signature) external returns (bool, address);

    function validateExecutionDataOnlyReturnInteractionContract(uint256 _ethAmount, bytes calldata _executionData) external returns (bool, address);

    function validateExecutionSignature(address _executor, uint256 _nonce, uint256 _timeout, uint256 _ethAmount, bytes calldata _executionData, bytes calldata _signature) external returns (bool);

    function getNonce(address _eoa7702, address _executor) external view returns (uint256);
}