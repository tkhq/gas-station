// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IBatchExecution} from "./IBatchExecution.sol";

interface ITKGasStation is IBatchExecution {

    function tkGasDelegate() external view returns (address);

     // Execute functions
    function execute(address _target, bytes calldata data) external returns (bool, bytes memory);

    function execute(address _target, address _to, uint256 _ethAmount, bytes calldata _data) external returns (bool, bytes memory);

    function approveThenExecute(address _target, bytes calldata data) external returns (bool, bytes memory);

    function approveThenExecute(address _target, address _to, uint256 _ethAmount, address _erc20, address _spender, uint256 _approveAmount, bytes calldata _data) external returns (bool, bytes memory);

    // Session execute functions
    function executeSession(address _target, bytes calldata data) external returns (bool, bytes memory);

    function executeSession(address _target, address _to, uint256 _ethAmount, bytes calldata _data) external returns (bool, bytes memory);

    function executeBatch(address _target, bytes calldata data) external returns (bool, bytes[] memory);

    function executeBatch(address _target, IBatchExecution.Call[] calldata _calls, bytes calldata _data) external returns (bool, bytes[] memory);

    // Batch execute functions
    function executeBatchSession(address _target, bytes calldata data) external returns (bool, bytes[] memory);

    function executeBatchSession(address _target, IBatchExecution.Call[] calldata _calls, bytes calldata _data) external returns (bool, bytes[] memory);

    // Arbitrary execute functions
    function executeSessionArbitrary(address _target, bytes calldata data) external returns (bool, bytes memory);

    function executeSessionArbitrary(address _target, address _to, uint256 _ethAmount, bytes calldata _data) external returns (bool, bytes memory);

    function executeBatchSessionArbitrary(address _target, bytes calldata data) external returns (bool, bytes[] memory);

    function executeBatchSessionArbitrary(address _target, IBatchExecution.Call[] calldata _calls, bytes calldata _data) external returns (bool, bytes[] memory);
    
    function burnNonce(address _targetEoA, bytes calldata _signature, uint128 _nonce) external;

    function getNonce(address _targetEoA) external view returns (uint128);

    function isDelegated(address _targetEoA) external view returns (bool);
}