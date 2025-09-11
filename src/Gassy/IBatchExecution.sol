// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

// Shared interface for batch execution structures
interface IBatchExecution {
    struct Execution {
        address outputContract;
        uint256 ethAmount;
        bytes arguments;
    }
}
