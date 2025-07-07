// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

interface ITKSmartWalletManager {
    function validateAllReturnInteractionContract(address _fundingEOA, address _executor, uint256 _timeout, bytes calldata _signature, bytes memory _executionData) external view returns (bool, address);
}