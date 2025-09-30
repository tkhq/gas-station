// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IBatchExecution} from "./IBatchExecution.sol";

interface ITKGasDelegate {
    // Execute functions
    function execute(bytes calldata _signature, uint128 _nonce, address _outputContract, bytes calldata _arguments)
        external
        returns (bool, bytes memory);

    function execute(
        bytes calldata _signature,
        uint128 _nonce,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments
    ) external returns (bool, bytes memory);

    // Session execute functions
    function executeSession(
        bytes calldata _signature,
        uint128 _counter,
        uint128 _deadline,
        address _outputContract,
        bytes calldata _arguments
    ) external returns (bool, bytes memory);
    function executeSession(
        bytes calldata _signature,
        uint128 _counter,
        uint128 _deadline,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments
    ) external returns (bool, bytes memory);

    // Batch execute functions
    function executeBatchSession(
        bytes calldata _signature,
        uint128 _counter,
        uint128 _deadline,
        address _sender,
        IBatchExecution.Call[] calldata _calls
    ) external returns (bool, bytes[] memory);
    
    function executeBatch(bytes calldata _signature, uint128 _nonce, IBatchExecution.Call[] calldata _calls)
        external
        returns (bool, bytes[] memory);

    // Arbitrary execute functions
    function executeSessionArbitrary(
        bytes calldata _signature,
        uint128 _counter,
        uint128 _deadline,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments
    ) external returns (bool, bytes memory);
    function executeSessionArbitrary(
        bytes calldata _signature,
        uint128 _counter,
        uint128 _deadline,
        address _outputContract,
        bytes calldata _arguments
    ) external returns (bool, bytes memory);
    function executeBatchSessionArbitrary(
        bytes calldata _signature,
        uint128 _counter,
        uint128 _deadline,
        IBatchExecution.Call[] calldata _calls
    ) external returns (bool, bytes[] memory);

    // Burn functions
    function burnNonce(bytes calldata _signature, uint128 _nonce) external;
    function burnSessionCounter(bytes calldata _signature, uint128 _counter, address _sender) external;

    // Lense functions
    function nonce() external view returns (uint128);
    function sessionCounter() external view returns (uint128);
}
