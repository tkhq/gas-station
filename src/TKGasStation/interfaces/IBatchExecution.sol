// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

interface IBatchExecution {
    struct Call {
        address to;
        uint256 value;
        bytes data;
    }
}
