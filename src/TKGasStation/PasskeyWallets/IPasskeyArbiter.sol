// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

interface IPasskeyArbiter {
    function validateSignature(bytes32 _hash, bytes calldata _signature) external view returns (bool);
    //function validateSignature(address _target, bytes32 _hash, bytes calldata _signature) external view returns (bool);
}
