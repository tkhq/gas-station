// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {EIP712} from "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import {Ownable} from "openzeppelin-contracts/contracts/access/Ownable.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

import {ITKSmartWalletManager} from "./Interfaces/ITKSmartWalletManager.sol";
import {AbstractTKSmartWalletManager} from "./AbstractTKSmartWalletManager.sol";


contract TKSmartWalletManager is Ownable, AbstractTKSmartWalletManager {

    error ExecutionNotAllowed();
    error FunctionNotAllowed(bytes4 functionId);
    error ExecutionFailed();
    error ValidationFailed();
    error Timeout();
    error AllowedFunctionsTooLong();
    error InvalidNonce();

    bytes4 public constant EMPTY_FUNCTIONID = 0x00000000;
    
    bool public allowExecution; 

    bytes32 public immutable allowedFunctions; // This saves about 1/4 gas compared to a mapping on each execution, but it limits the number of allowed functions to 8

    mapping(address eoa7702 => mapping(address executor => uint256)) public nonces;

    constructor(
        string memory _name,
        string memory _version,
        address _owner,
        address _interactionContract,
        bytes4[] memory _allowedFunctions
    ) AbstractTKSmartWalletManager(_name, _version, _interactionContract) Ownable(_owner) {
        if (_allowedFunctions.length > 8) {
            revert AllowedFunctionsTooLong();
        }

        bytes32 tmpAllowedFunctions = 0;
        for (uint256 i = 0; i < _allowedFunctions.length; i++) {
            tmpAllowedFunctions = bytes32(uint256(tmpAllowedFunctions) | (uint256(uint32(_allowedFunctions[i])) << ( (7 - i) * 32)));
        }
        allowedFunctions = tmpAllowedFunctions;
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

        bytes4 functionId = bytes4(_executionData[:4]);
        if (!isAllowedFunction(functionId)) {
            revert FunctionNotAllowed(functionId);
        }
        
        if (nonces[msg.sender][_executor] != _nonce) {
            revert InvalidNonce();
        }
        nonces[msg.sender][_executor]++;

        bool isValid = _validateExecutionSignature(msg.sender, _executor, _nonce, _timeout, _ethAmount, _executionData, _signature);
        
        return (isValid, interactionContract);
    }

    function validateExecutionDataOnlyReturnInteractionContract(uint256 /* _ethAmount */, bytes calldata _executionData) external view override returns (bool, address) {
        if (!allowExecution) {
            revert ExecutionNotAllowed();
        }

        bytes4 functionId = bytes4(_executionData[:4]);
        if (!isAllowedFunction(functionId)) {

            revert FunctionNotAllowed(functionId);
        }
        return (true, interactionContract);
    }

    function validateExecutionSignature(address _executor, uint256 _nonce, uint256 _timeout, uint256 _ethAmount, bytes calldata _executionData, bytes calldata _signature) external override returns (bool) {
        if (block.timestamp > _timeout) {
            revert Timeout();
        }

        if (nonces[msg.sender][_executor] != _nonce) {
            revert InvalidNonce();
        }
        nonces[msg.sender][_executor]++;

        return _validateExecutionSignature(msg.sender, _executor, _nonce, _timeout, _ethAmount, _executionData, _signature);
    }

    function getNonce(address _eoa7702, address _executor) external view override returns (uint256) {
        return nonces[_eoa7702][_executor];
    }

    function isAllowedFunction(bytes4 _functionId) public view returns (bool) {
        if (allowedFunctions == 0) {
            return true;
        }
        for (uint256 i = 0; i < 8; i++) {
            bytes4 tmp = bytes4(allowedFunctions >> (i * 32));
            if (tmp == _functionId) {
                return true; // function id has been found
            }
            if (tmp == EMPTY_FUNCTIONID) {
                return false; // no more functions to check
            }
        }
        return false;
    }
}
