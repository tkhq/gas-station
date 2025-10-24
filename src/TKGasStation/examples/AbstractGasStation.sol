// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ITKGasStation} from "../interfaces/ITKGasStation.sol";
import {IBatchExecution} from "../interfaces/IBatchExecution.sol";
import {IsDelegated} from "./IsDelegated.sol";
import {ITKGasDelegate} from "../interfaces/ITKGasDelegate.sol";

abstract contract AbstractGasStation is ITKGasStation {
    error NoEthAllowed();
    error NotDelegated();

    address public immutable tkGasDelegate;

    constructor(address _tkGasDelegate) {
        tkGasDelegate = _tkGasDelegate;
    }

    receive() external payable {
        revert NoEthAllowed();
    }

    function _isDelegated(address _targetEoA) internal view returns (bool) {
        return IsDelegated.isDelegatedTo(_targetEoA, tkGasDelegate);
    }

    // Execute functions
    function executeReturns(address _target, address _to, uint256 _ethAmount, bytes calldata _data)
        external
        virtual
        returns (bytes memory);

    function execute(address _target, address _to, uint256 _ethAmount, bytes calldata _data) external virtual;

    // ApproveThenExecute functions
    function approveThenExecuteReturns(
        address _target,
        address _to,
        uint256 _ethAmount,
        address _erc20,
        address _spender,
        uint256 _approveAmount,
        bytes calldata _data
    ) external virtual returns (bytes memory) {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        bytes memory result =
            ITKGasDelegate(_target).approveThenExecuteReturns(_to, _ethAmount, _erc20, _spender, _approveAmount, _data);
        return result;
    }

    function approveThenExecute(
        address _target,
        address _to,
        uint256 _ethAmount,
        address _erc20,
        address _spender,
        uint256 _approveAmount,
        bytes calldata _data
    ) external virtual {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        ITKGasDelegate(_target).approveThenExecute(_to, _ethAmount, _erc20, _spender, _approveAmount, _data);
    }

    // Batch execute functions
    function executeBatchReturns(address _target, IBatchExecution.Call[] calldata _calls, bytes calldata _data)
        external
        virtual
        returns (bytes[] memory)
    {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        bytes[] memory results = ITKGasDelegate(_target).executeBatchReturns(_calls, _data);
        return results;
    }

    function executeBatch(address _target, IBatchExecution.Call[] calldata _calls, bytes calldata _data)
        external
        virtual
    {
        if (!_isDelegated(_target)) {
            revert NotDelegated();
        }
        ITKGasDelegate(_target).executeBatch(_calls, _data);
    }

    function burnNonce(address _targetEoA, bytes calldata _signature, uint128 _nonce) external virtual {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        ITKGasDelegate(_targetEoA).burnNonce(_signature, _nonce);
    }

    function getNonce(address _targetEoA) external view returns (uint128) {
        if (!_isDelegated(_targetEoA)) {
            revert NotDelegated();
        }
        uint128 nonce = ITKGasDelegate(_targetEoA).nonce();
        return nonce;
    }

    function isDelegated(address _targetEoA) external view returns (bool) {
        return _isDelegated(_targetEoA);
    }
}
