// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {EIP712} from "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import {Ownable} from "openzeppelin-contracts/contracts/access/Ownable.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

import {ITKSmartWalletManager} from "./interfaces/ITKSmartWalletManager.sol";
import {AbstractTKSmartWalletManager} from "./AbstractTKSmartWalletManager.sol";

contract TKSmartWalletManager is Ownable, AbstractTKSmartWalletManager {
    error ExecutionNotAllowed();
    error FunctionNotAllowed(bytes4 functionId);
    error ExecutionFailed();
    error ValidationFailed();
    error Timeout();

    bool public allowExecution;

    constructor(
        string memory _name,
        string memory _version,
        address _owner,
        address _interactionContract
    ) AbstractTKSmartWalletManager(_name, _version, _interactionContract) Ownable(_owner) {
        allowExecution = true;
    }

    function freezeExecution() external onlyOwner {
        allowExecution = false;
    }

    function unfreezeExecution() external onlyOwner {
        allowExecution = true;
    }

    function validateAllReturnInteractionContract(address _executor, uint256 _nonce, uint256 _timeout, uint256 _ethAmount, bytes calldata _executionData, bytes calldata _signature) external override returns (bool, address) {
        if (!allowExecution) {
            revert ExecutionNotAllowed();
        }
        if (block.timestamp > _timeout) {
            revert Timeout();
        }
        _validateAndIncrementNonce(msg.sender, _executor, _nonce);
        bool isValid = _validateExecutionSignature(msg.sender, _executor, _nonce, _timeout, _ethAmount, _executionData, _signature);
        return (isValid, interactionContract);
    }

    function validateExecutionDataOnlyReturnInteractionContract(uint256 /* _ethAmount */, bytes calldata /* _executionData */) external view override returns (bool, address) {
        if (!allowExecution) {
            revert ExecutionNotAllowed();
        }
        return (true, interactionContract);
    }

}
