// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IBatchExecution} from "./IBatchExecution.sol";

interface ITKGasDelegate is IBatchExecution {
    function nonce() external view returns (uint128);
    function getNonce(uint64 _prefix) external view returns (uint128);

    function validateSignature(bytes32 _hash, bytes calldata _signature) external view returns (bool);

    function checkSessionCounterExpired(uint128 _counter) external view returns (bool);

    function supportsInterface(bytes4 _interfaceId) external pure returns (bool);

    // Execute functions
    function executeReturns(bytes calldata _data) external returns (bytes memory);

    function execute(bytes calldata _data) external;

    function executeNoValueNoReturn(bytes calldata _data) external;

    function executeReturns(address _to, uint256 _value, bytes calldata _data) external returns (bytes memory);

    function execute(address _to, uint256 _value, bytes calldata _data) external;

    //ApproveThenExecute functions

    function approveThenExecuteReturns(bytes calldata _data) external returns (bytes memory);

    function approveThenExecute(bytes calldata _data) external;

    function approveThenExecuteReturns(
        address _to,
        uint256 _value,
        address _erc20,
        address _spender,
        uint256 _approveAmount,
        bytes calldata _data
    ) external returns (bytes memory);

    function approveThenExecute(
        address _to,
        uint256 _value,
        address _erc20,
        address _spender,
        uint256 _approveAmount,
        bytes calldata _data
    ) external;

    // Batch execute functions

    function executeBatchReturns(bytes calldata _data) external returns (bytes[] memory);

    function executeBatch(bytes calldata _data) external;

    function executeBatchReturns(IBatchExecution.Call[] calldata _calls, bytes calldata _data)
        external
        returns (bytes[] memory);

    function executeBatch(IBatchExecution.Call[] calldata _calls, bytes calldata _data) external;

    // Batch session execute functions
    function executeBatchSessionReturns(bytes calldata _data) external returns (bytes[] memory);

    function executeBatchSession(bytes calldata _data) external;

    function executeBatchSessionReturns(IBatchExecution.Call[] calldata _calls, bytes calldata _data)
        external
        returns (bytes[] memory);

    function executeBatchSession(IBatchExecution.Call[] calldata _calls, bytes calldata _data) external;

    // Session execute functions
    function executeSessionReturns(bytes calldata _data) external returns (bytes memory);

    function executeSession(bytes calldata _data) external;

    function executeSessionReturns(address _to, uint256 _value, bytes calldata _data) external returns (bytes memory);

    function executeSession(address _to, uint256 _value, bytes calldata _data) external;

    // Arbitrary session functions
    function executeSessionArbitraryReturns(bytes calldata _data) external returns (bytes memory);

    function executeSessionArbitrary(bytes calldata _data) external;

    function executeSessionArbitraryReturns(address _to, uint256 _value, bytes calldata _data)
        external
        returns (bytes memory);

    function executeSessionArbitrary(address _to, uint256 _value, bytes calldata _data) external;

    // Arbitrary batch session functions

    function executeBatchSessionArbitraryReturns(bytes calldata _data) external returns (bytes[] memory);

    function executeBatchSessionArbitrary(bytes calldata _data) external;

    function executeBatchSessionArbitraryReturns(IBatchExecution.Call[] calldata _calls, bytes calldata _data)
        external
        returns (bytes[] memory);

    function executeBatchSessionArbitrary(IBatchExecution.Call[] calldata _calls, bytes calldata _data) external;

    // Burn functions
    function burnNonce(bytes calldata _signature, uint128 _nonce) external;
    function burnSessionCounter(bytes calldata _signature, uint128 _counter) external;
    function burnNonce() external;
    function burnNonce(uint64 _prefix) external;
    function burnSessionCounter(uint128 _counter) external;

    // Hash functions
    function hashExecution(uint128 _nonce, uint32 _deadline, address _to, uint256 _value, bytes calldata _data)
        external
        view
        returns (bytes32);

    function hashBurnNonce(uint128 _nonce) external view returns (bytes32);

    function hashApproveThenExecute(
        uint128 _nonce,
        uint32 _deadline,
        address _erc20Contract,
        address _spender,
        uint256 _approveAmount,
        address _to,
        uint256 _value,
        bytes calldata _data
    ) external view returns (bytes32);

    function hashSessionExecution(uint128 _counter, uint32 _deadline, address _sender, address _to)
        external
        view
        returns (bytes32);

    function hashArbitrarySessionExecution(uint128 _counter, uint32 _deadline, address _sender)
        external
        view
        returns (bytes32);

    function hashBatchExecution(uint128 _nonce, uint32 _deadline, IBatchExecution.Call[] calldata _calls)
        external
        view
        returns (bytes32);

    function hashBurnSessionCounter(uint128 _counter) external view returns (bytes32);
}
