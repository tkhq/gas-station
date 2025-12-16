// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {TransientSignature} from "../structs/TransientSignature.sol";

/// @notice Interface for transient multisig storage operations
interface ITransientMultiSigStorage {
    /// @notice Sets multiple transient signatures in a batch
    /// @param _target The target wallet address
    /// @param _signatures Array of transient signatures to set
    /// @return signature The concatenated signature bytes
    function setTransientSignatures(address _target, TransientSignature[] calldata _signatures) external returns (bytes memory);

    /// @notice Sets a transient signature (auto-detects passkey vs address signature based on length)
    /// @param _target The target wallet address
    /// @param _index The signature index
    /// @param _signature The signature bytes (64 bytes for passkey, 65 bytes for address)
    function setTransientSignature(address _target, uint8 _index, bytes calldata _signature) external;

    /// @notice Sets a transient passkey signature (64 bytes)
    /// @param _target The target wallet address
    /// @param _index The signature index
    /// @param _signature The passkey signature bytes (64 bytes: r and s)
    function setTransientPassKeySignature(address _target, uint8 _index, bytes calldata _signature) external;

    /// @notice Sets a transient address signature (65 bytes)
    /// @param _target The target wallet address
    /// @param _index The signature index
    /// @param _signature The address signature bytes (65 bytes: r, s, and v)
    function setTransientAddressSignature(address _target, uint8 _index, bytes calldata _signature) external;

    /// @notice Gets a transient passkey signature
    /// @param _target The target wallet address
    /// @param _index The signature index
    /// @return first32 The first 32 bytes of the signature (r)
    /// @return second32 The second 32 bytes of the signature (s)
    function getTransientPassKeySignature(address _target, uint8 _index)
        external
        view
        returns (bytes32 first32, bytes32 second32);

    /// @notice Gets a transient address signature
    /// @param _target The target wallet address
    /// @param _index The signature index
    /// @return r The r component of the signature
    /// @return s The s component of the signature
    /// @return v The v component of the signature
    function getTransientAddressSignature(address _target, uint8 _index)
        external
        view
        returns (bytes32 r, bytes32 s, bytes1 v);
}

