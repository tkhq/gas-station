// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IBatchExecution} from "./IBatchExecution.sol";

interface ITKGasDelegate is IBatchExecution {
    // State struct
    struct State {
        uint128 sessionCounter;
        uint128 nonce;
    }
    
    // Execute functions
    function execute(bytes calldata data) external returns (bool, bytes memory);

    function executeNoValue(bytes calldata data) external returns (bool, bytes memory);

    // Session execute functions
    function executeSession(bytes calldata data) external returns (bool, bytes memory);

    function executeBatch(bytes calldata data) external returns (bool, bytes[] memory);

    // Batch execute functions
    function executeBatchSession(bytes calldata data) external returns (bool, bytes[] memory);
    // Arbitrary execute functions
    function executeSessionArbitrary(bytes calldata data) external returns (bool, bytes memory);

    function executeBatchSessionArbitrary(bytes calldata data) external returns (bool, bytes[] memory);

    // Burn functions
    function burnNonce(bytes calldata _signature, uint128 _nonce) external;
    function burnSessionCounter(bytes calldata _signature, uint128 _counter, address _sender) external;

    // State access
    function state() external view returns (uint128 sessionCounter, uint128 nonce);
}
