// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {EIP712Upgradeable} from "openzeppelin-contracts-upgradeable/contracts/utils/cryptography/EIP712Upgradeable.sol";
import {OwnableUpgradeable} from "openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {Initializable} from "openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";

/**
 * @title AbstractTKSmartWallet
 * @dev Abstract contract implementing EIP-7702 delegation functionality for smart wallets
 * @notice This contract provides the foundation for EIP-7702 compliant smart wallets
 * @author TK
 */
abstract contract AbstractTKSmartWallet is Initializable, OwnableUpgradeable {
    

    error ExecutionNotAllowed();
    error FunctionNotAllowed();
    error ExecutionFailed();

    address public interactionContract; //160
    bool public functionsLimited; //8
    bool public allowExecution; //8


    mapping(bytes4 => bool) public allowedFunctions;


    modifier onlyAllowExecution() {
        if (!allowExecution) {
            revert ExecutionNotAllowed();
        }
        _;
    }
    
    function initialize(address _interactionContract, address _owner, bytes4[] memory _allowedFunctions) public initializer {
        __Ownable_init(_owner);
        // __EIP712_init("TKSmartWallet", "1");
        interactionContract = _interactionContract;
        functionsLimited = _allowedFunctions.length > 0;
        for (uint256 i = 0; i < _allowedFunctions.length; i++) {
            allowedFunctions[_allowedFunctions[i]] = true;
        }
        allowExecution = true;
    }

    function execute(bytes calldata _signature, bytes4 _functionId, bytes memory _data) external onlyAllowExecution {
        if (functionsLimited && !allowedFunctions[_functionId]) {
            revert FunctionNotAllowed();
        }
        /*
        (bool success, bytes memory result) = interactionContract.call(_functionId, _data);
        if (!success) {
            revert("Execution failed");
        }
        */
    }

    function freezeExecution() external onlyOwner {
        allowExecution = false;
    }
    function unfreezeExecution() external onlyOwner {
        allowExecution = true;
    }

    function _verifySignature(bytes calldata _signature, bytes4 _functionId, bytes memory _data) internal view returns (bool) {
        return true;
    }
}
