// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IBatchExecution} from "./IBatchExecution.sol";

interface ITKGasStation is IBatchExecution {
    function TK_GAS_DELEGATE() external view returns (address);

    // Execute functions
    function executeReturns(address _target, address _to, uint256 _ethAmount, bytes calldata _data)
        external
        returns (bytes memory);
    function execute(address _target, address _to, uint256 _ethAmount, bytes calldata _data) external;

    // ApproveThenExecute functions
    function approveThenExecuteReturns(
        address _target,
        address _to,
        uint256 _ethAmount,
        address _erc20,
        address _spender,
        uint256 _approveAmount,
        bytes calldata _data
    ) external returns (bytes memory);
    function approveThenExecute(
        address _target,
        address _to,
        uint256 _ethAmount,
        address _erc20,
        address _spender,
        uint256 _approveAmount,
        bytes calldata _data
    ) external;

    // Batch execute functions
    function executeBatchReturns(address _target, IBatchExecution.Call[] calldata _calls, bytes calldata _data)
        external
        returns (bytes[] memory);
    function executeBatch(address _target, IBatchExecution.Call[] calldata _calls, bytes calldata _data) external;

    function burnNonce(address _targetEoA, bytes calldata _signature, uint128 _nonce) external;

    function getNonce(address _targetEoA, uint64 _prefix) external view returns (uint128);
    function getNonce(address _targetEoA) external view returns (uint128);

    function isDelegated(address _targetEoA) external view returns (bool);
}
