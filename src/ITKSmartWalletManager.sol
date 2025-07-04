// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

interface ITKSmartWalletManager {
    function validateAllReturnInteractionContract(bytes4 _functionId, address _fundingEOA, address _executor, uint256 _timeout, bytes calldata _signature) external view returns (bool, address);
}