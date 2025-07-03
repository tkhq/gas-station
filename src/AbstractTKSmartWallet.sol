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
    error ExecutorBanned();

    address public interactionContract; //160
    bool public functionsLimited; //8
    bool public allowExecution; //8

    bytes32 public constant TK_SMART_WALLET_EXECUTE_TYPEHASH =
        keccak256("TKSmartWalletExecute(address smartWalletContract, address fundingEOA, address executor, uint256 timeout)");


    mapping(bytes4 => bool) public allowedFunctions; // TODO find a more efficient way to store this, maybe to include function types/etc

    mapping(address => bool) public bannedExecutors;

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

    function execute(address _fundingEOA, uint256 _timeout, bytes calldata _signature, bytes4 _functionId, bytes memory _data) external onlyAllowExecution {
        if (functionsLimited && !allowedFunctions[_functionId]) {
            revert FunctionNotAllowed();
        }

        address executor = msg.sender;
        if (bannedExecutors[executor]) {
            revert ExecutorBanned();
        }

        address 
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
    function banExecutor(address _executor) external onlyOwner { // todo allow an executor to ban itself as a "logout"
        bannedExecutors[_executor] = true;
    }
    function unbanExecutor(address _executor) external onlyOwner {
        bannedExecutors[_executor] = false;
    }

    function _verifySignature(bytes calldata _signature, bytes memory _data) internal view returns (bool) {
        return true;
    }
}
