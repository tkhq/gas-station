// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {EIP712} from "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import {Ownable} from "openzeppelin-contracts/contracts/access/Ownable.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

import {ITKSmartWalletManager} from "./ITKSmartWalletManager.sol";
import {AbstractTKSmartWalletManager} from "./AbstractTKSmartWalletManager.sol";


contract TKSmartWalletManager is Ownable, AbstractTKSmartWalletManager {

    error ExecutionNotAllowed();
    error FunctionNotAllowed(bytes4 functionId);
    error ExecutionFailed();
    error ExecutorBanned();
    error ValidationFailed();
    error Timeout();
    error AllowedFunctionsTooLong();

    bytes4 public constant EMPTY_FUNCTIONID = 0x00000000;
    
    bool public allowExecution; 

    bytes32 public immutable allowedFunctions; // This saves about 1/4 gas compared to a mapping on each execution, but it limits the number of allowed functions to 8

    mapping(address => bool) public bannedExecutors; 

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

    function banExecutor(address _executor) external onlyOwner { 
        bannedExecutors[_executor] = true;
    }

    function unbanExecutor(address _executor) external onlyOwner {
        bannedExecutors[_executor] = false;
    }

    function validateAllReturnInteractionContract(address _fundingEOA, address _executor, uint256 _timeout, bytes calldata _signature, uint256 /* _ethAmount */, bytes calldata _executionData) external view override returns (bool, address) {
        if (!allowExecution) {
            revert ExecutionNotAllowed();
        }

        if (block.timestamp > _timeout) {
            revert Timeout();
        }

        if (bannedExecutors[_executor]) {
            revert ExecutorBanned();
        }

        bytes4 functionId = bytes4(_executionData[:4]);
        if (!isAllowedFunction(functionId)) {

            revert FunctionNotAllowed(functionId);
        }

        if (!validateExecutionSignature(_fundingEOA, _executor, _timeout, _signature)) {
            revert ValidationFailed();
        }
        
        // _ethAmount is available but not enforced - can be used for future validation logic
        // For now, we just ignore it
        
        return (true, interactionContract);
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
