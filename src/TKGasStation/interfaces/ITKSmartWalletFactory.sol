// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IArbiter} from "./IArbiter.sol";
import {ITransientMultiSigStorage} from "./ITransientMultiSigStorage.sol";
import {PublicKey} from "../structs/PublicKey.sol";

/// @notice Interface for TKSmartWalletFactory contract
interface ITKSmartWalletFactory is IArbiter, ITransientMultiSigStorage {
    /// @notice Returns the implementation address used for cloning wallets
    /// @return The address of the TKSmartWalletDelegate implementation contract
    function IMPLEMENTATION() external view returns (address);

    /// @notice Creates a wallet from a passkey public key
    /// @param _x The x coordinate of the public key
    /// @param _y The y coordinate of the public key
    /// @return instance The address of the created wallet
    function createWallet(bytes32 _x, bytes32 _y) external returns (address instance);

    /// @notice Creates a wallet from an EOA address
    /// @param _address The EOA address to create the wallet from
    /// @return instance The address of the created wallet
    function createWallet(address _address) external returns (address instance);

    /// @notice Creates a wallet with a custom rule set (multisig configuration)
    /// @param _mOf The minimum number of signatures required
    /// @param _publicKeys Array of public keys to include in the rule set
    /// @param _addresses Array of addresses to include in the rule set
    /// @param _salt The salt for deterministic address generation
    /// @return instance The address of the created wallet
    function createWallet(
        uint8 _mOf,
        PublicKey[] memory _publicKeys,
        address[] memory _addresses,
        bytes32 _salt
    ) external returns (address instance);
}

