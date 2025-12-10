// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {TKGasStation} from "./TKGasStation.sol";
import {ITKGasDelegate} from "./interfaces/ITKGasDelegate.sol";
import {IBatchExecution} from "./interfaces/IBatchExecution.sol";
import {IBundle} from "./interfaces/IBundle.sol";
import {LibTransient} from "solady/utils/LibTransient.sol";

contract TKBundledGasStation is TKGasStation {
    using LibTransient for *;

    event TargetNotDelegated(address indexed target);
    event BundleExecutionFailed(address indexed target, uint256 indexed index, bytes error);

    struct ReturnData {
        uint256 gasCost;
        bool success;
        bytes returnData;
    }

    // Transient storage slot seed for address-based lookups
    bytes32 private constant TRANSIENT_STORAGE_SEED = keccak256("TKBundledGasStation");

    constructor(address _tkGasDelegate) TKGasStation(_tkGasDelegate) {}

    /// @dev Computes a transient storage slot for an address
    function _getTransientSlot(address _addr) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(TRANSIENT_STORAGE_SEED, _addr));
    }

    /// @dev Sets a boolean value in transient storage for an address
    function _setTransientBool(address _addr, bool _value) internal {
        LibTransient.TBool storage ptr = LibTransient.tBool(_getTransientSlot(_addr));
        LibTransient.set(ptr, _value);
    }

    /// @dev Gets a boolean value from transient storage for an address
    function _getTransientBool(address _addr) internal returns (bool) {
        LibTransient.TBool storage ptr = LibTransient.tBool(_getTransientSlot(_addr));
        return LibTransient.get(ptr);
    }

    function _checkDelegated(address _target) internal returns (bool isDelegated) {
        isDelegated = _getTransientBool(_target);
        if (!isDelegated) {
            isDelegated = _isDelegated(_target);
            _setTransientBool(_target, isDelegated);
        }
    }

    function bundleCall(IBundle.BundleCall[] calldata _bundleExecutions) external {
        for (uint256 i = 0; i < _bundleExecutions.length; i++) {
            if (!_checkDelegated(_bundleExecutions[i].target)) {
                emit TargetNotDelegated(_bundleExecutions[i].target);
                continue;
            }
            IBundle.BundleCall calldata bundle = _bundleExecutions[i];
            (bool success, bytes memory returnData) = bundle.target.call{gas: bundle.gasLimit}(bundle.data);
            if (!success) {
                emit BundleExecutionFailed(bundle.target, i, returnData);
            }
        }
    }

    function bundleCallReturns(IBundle.BundleCall[] calldata _bundleExecutions)
        external
        returns (ReturnData[] memory)
    {
        ReturnData[] memory returnData = new ReturnData[](_bundleExecutions.length);
        bytes memory targetNotDelegatedData = hex"8fb54559";
        for (uint256 i = 0; i < _bundleExecutions.length; i++) {
            uint256 gasStart = gasleft();
            if (!_checkDelegated(_bundleExecutions[i].target)) {
                //returnData[i].success = false; // not needed since defaults to false, but leaving commented for clarity
                returnData[i].returnData = targetNotDelegatedData;
            } else {
                IBundle.BundleCall calldata bundle = _bundleExecutions[i];
                (bool success, bytes memory returnBytes) = bundle.target.call{gas: bundle.gasLimit}(bundle.data);
                returnData[i].success = success;
                returnData[i].returnData = returnBytes;
            }
            returnData[i].gasCost = gasStart - gasleft();
        }
        return returnData;
    }

    function bundleExecute(IBundle.BundleExecute[] calldata _bundleExecutes) external {
        for (uint256 i = 0; i < _bundleExecutes.length; i++) {
            if (!_checkDelegated(_bundleExecutes[i].target)) {
                emit TargetNotDelegated(_bundleExecutes[i].target);
                continue;
            }
            IBundle.BundleExecute calldata bundle = _bundleExecutes[i];
            try ITKGasDelegate(bundle.target).execute{gas: bundle.gasLimit}(bundle.to, bundle.value, bundle.data) {
                // Success - continue to next iteration
            } catch (bytes memory errorBytes) {
                emit BundleExecutionFailed(bundle.target, i, errorBytes);
            }
        }
    }

    function bundleExecuteReturns(IBundle.BundleExecute[] calldata _bundleExecutes)
        external
        returns (ReturnData[] memory)
    {
        ReturnData[] memory returnData = new ReturnData[](_bundleExecutes.length);
        bytes memory targetNotDelegatedData = hex"8fb54559";
        for (uint256 i = 0; i < _bundleExecutes.length; i++) {
            uint256 gasStart = gasleft();
            if (!_checkDelegated(_bundleExecutes[i].target)) {
                //returnData[i].success = false; // not needed since defaults to false, but leaving commented for clarity
                returnData[i].returnData = targetNotDelegatedData;
            } else {
                IBundle.BundleExecute calldata bundle = _bundleExecutes[i];
                try ITKGasDelegate(bundle.target).executeReturns(bundle.to, bundle.value, bundle.data) returns (
                    bytes memory returnBytes
                ) {
                    returnData[i].success = true;
                    returnData[i].returnData = returnBytes;
                } catch (bytes memory errorBytes) {
                    returnData[i].success = false;
                    returnData[i].returnData = errorBytes;
                }
            }
            returnData[i].gasCost = gasStart - gasleft();
        }
        return returnData;
    }
}
