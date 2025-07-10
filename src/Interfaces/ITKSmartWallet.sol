// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

interface ITKSmartWallet {

    function execute(uint256 _ethAmount, bytes calldata _executionData) external returns (bool success, bytes memory result);

    function executeMetaTx(address _executor, uint256 _nonce, uint256 _timeout, uint256 _ethAmount, bytes calldata _executionData, bytes calldata _signature) external returns (bool success, bytes memory result);

}