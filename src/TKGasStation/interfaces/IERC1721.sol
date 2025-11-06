// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

interface IERC1721 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4 magicValue);
}
