// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {PublicKey} from "./PublicKey.sol";

/// @notice Struct representing a rule set for wallet authorization
struct RuleSet {
    uint8 mOf;
    uint8 n;
    PublicKey[] publicKeys;
    address[] addresses;
}
