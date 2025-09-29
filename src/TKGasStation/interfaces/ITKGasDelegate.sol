// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IBatchExecution} from "./IBatchExecution.sol";

interface ITKGasDelegate {
    // Execute functions
    function execute(uint128 _nonce, address _outputContract, bytes calldata _arguments, bytes calldata _signature)
        external
        returns (bool, bytes memory);
    function execute(
        uint128 _nonce,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments,
        bytes calldata _signature
    ) external returns (bool, bytes memory);

    // Session execute functions
    function executeSession(
        uint128 _counter,
        uint128 _deadline,
        address _outputContract,
        bytes calldata _arguments,
        bytes calldata _signature
    ) external returns (bool, bytes memory);
    function executeSession(
        uint128 _counter,
        uint128 _deadline,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments,
        bytes calldata _signature
    ) external returns (bool, bytes memory);

    // Batch execute functions
    function executeBatchSession(
        uint128 _counter,
        uint128 _deadline,
        address _sender,
        IBatchExecution.Execution[] calldata _executions,
        bytes calldata _signature
    ) external returns (bool, bytes[] memory);
    function executeBatch(uint128 _nonce, IBatchExecution.Execution[] calldata _executions, bytes calldata _signature)
        external
        returns (bool, bytes[] memory);

    // Arbitrary execute functions
    function executeSessionArbitrary(
        uint128 _counter,
        uint128 _deadline,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments,
        bytes calldata _signature
    ) external returns (bool, bytes memory);
    function executeSessionArbitrary(
        uint128 _counter,
        uint128 _deadline,
        address _outputContract,
        bytes calldata _arguments,
        bytes calldata _signature
    ) external returns (bool, bytes memory);
    function executeBatchSessionArbitrary(
        uint128 _counter,
        uint128 _deadline,
        IBatchExecution.Execution[] calldata _executions,
        bytes calldata _signature
    ) external returns (bool, bytes[] memory);

    // Burn functions
    function burnNonce(uint128 _nonce, bytes calldata _signature) external;
    function burnSessionCounter(uint128 _counter, address _sender, bytes calldata _signature) external;

    // Lense functions
    function nonce() external view returns (uint128);
    function sessionCounter() external view returns (uint128);
}
