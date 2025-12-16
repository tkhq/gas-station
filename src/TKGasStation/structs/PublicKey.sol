// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @notice Struct representing a P-256 public key
struct PublicKey {
    bytes32 x;
    bytes32 y;
}
