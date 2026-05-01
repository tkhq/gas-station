// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

interface IInitializableDelegate {
    /// @notice This is the error that is thrown when the caller is not the initializer
    error NotAuthorized();

    /// @notice This is the error that is thrown when the contract is already initialized
    error AlreadyInitialized();

    function initialize(bytes memory _data) external returns (bytes memory);
}
