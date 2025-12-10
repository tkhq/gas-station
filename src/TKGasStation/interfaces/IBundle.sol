// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

interface IBundle {
    struct BundleCall {
        address target;
        uint256 gasLimit;
        bytes data; // completely arbitrary data sent to the target, could call the fallback function or anything else
    }

    struct BundleExecute {
        // For use with the execute functions only
        address target;
        uint256 gasLimit;
        address to;
        uint256 value;
        bytes data;
    }
}
