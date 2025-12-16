// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @notice Struct representing a transient signature for batch operations
struct TransientSignature {
    bytes signature;
    uint8 index;  // expect the offchain interaction to provide the index via look up in the view function 
}
