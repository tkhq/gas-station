// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IBatchExecution} from "./IBatchExecution.sol";

interface ITKGasDelegate is IBatchExecution {
    function nonce() external view returns (uint128);

    function checkSessionCounterExpired(uint128 _counter) external view returns (bool);

    // Execute functions
    function execute(bytes calldata data) external returns (bytes memory);

    function executeNoReturn(bytes calldata data) external;

    function execute(address _to, uint256 _ethAmount, bytes calldata _data) external returns (bytes memory);

    function executeNoReturn(address _to, uint256 _ethAmount, bytes calldata _data) external;

    //ApproveThenExecute functions

    function approveThenExecute(bytes calldata data) external returns (bytes memory);

    function approveThenExecuteNoReturn(bytes calldata data) external;

    function approveThenExecute(
        address _to,
        uint256 _ethAmount,
        address _erc20,
        address _spender,
        uint256 _approveAmount,
        bytes calldata _data
    ) external returns (bytes memory);

    function approveThenExecuteNoReturn(
        address _to,
        uint256 _ethAmount,
        address _erc20,
        address _spender,
        uint256 _approveAmount,
        bytes calldata _data
    ) external;

    // Batch execute functions

    function executeBatch(bytes calldata _data) external returns (bytes[] memory);

    function executeBatchNoReturn(bytes calldata _data) external;

    function executeBatch(IBatchExecution.Call[] calldata _calls, bytes calldata _data)
        external
        returns (bytes[] memory);

    function executeBatchNoReturn(IBatchExecution.Call[] calldata _calls, bytes calldata _data) external;

    // Batch session execute functions
    function executeBatchSession(bytes calldata _data) external returns (bytes[] memory);

    function executeBatchSessionNoReturn(bytes calldata _data) external;

    function executeBatchSession(IBatchExecution.Call[] calldata _calls, bytes calldata _data)
        external
        returns (bytes[] memory);

    function executeBatchSessionNoReturn(IBatchExecution.Call[] calldata _calls, bytes calldata _data) external;

    // Session execute functions
    function executeSession(bytes calldata data) external returns (bytes memory);

    function executeSessionNoReturn(bytes calldata data) external;

    function executeSession(address _to, uint256 _ethAmount, bytes calldata _data) external returns (bytes memory);

    function executeSessionNoReturn(address _to, uint256 _ethAmount, bytes calldata _data) external;

    // Arbitrary session functions
    function executeSessionArbitrary(bytes calldata data) external returns (bytes memory);

    function executeSessionArbitraryNoReturn(bytes calldata data) external;

    function executeSessionArbitrary(address _to, uint256 _ethAmount, bytes calldata _data)
        external
        returns (bytes memory);

    function executeSessionArbitraryNoReturn(address _to, uint256 _ethAmount, bytes calldata _data) external;

    // Arbitrary batch session functions

    function executeBatchSessionArbitrary(bytes calldata data) external returns (bytes[] memory);

    function executeBatchSessionArbitraryNoReturn(bytes calldata data) external;

    function executeBatchSessionArbitrary(IBatchExecution.Call[] calldata _calls, bytes calldata _data)
        external
        returns (bytes[] memory);

    function executeBatchSessionArbitraryNoReturn(IBatchExecution.Call[] calldata _calls, bytes calldata _data)
        external;

    // Burn functions
    function burnNonce(bytes calldata _signature, uint128 _nonce) external;
    function burnSessionCounter(bytes calldata _signature, uint128 _counter, address _sender) external;
    function burnNonce() external;
    function burnSessionCounter(uint128 _counter) external;
}
