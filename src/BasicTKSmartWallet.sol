// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ITKSmartWalletManager} from "./interfaces/ITKSmartWalletManager.sol";
import {ITKSmartWallet} from "./Interfaces/ITKSmartWallet.sol";

contract BasicTKSmartWallet is ITKSmartWallet {

    error ExecutionNotAllowed();
    error FunctionNotAllowed();
    error ExecutionFailed();
    error ExecutorBanned();
    error ValidationFailed();
    error NotSelf();
    error ExecutorNotInitialized();
    error ExecutorTimeout();
    error InvalidFunctionId();
    error ZeroAddress();

    address public immutable interactionContract; 
    bool public immutable useManager;
    
    bytes32 public immutable allowedFunctions;

    mapping(address => uint256) public timeOuts;

    constructor(
        address _interactionContract,
        bool _useManager,
        bytes4[] memory _allowedFunctions
    ) {
        if (_interactionContract == address(0)) {
            revert ZeroAddress();
        }
        interactionContract = _interactionContract;
        useManager = _useManager;
        // Pack up to 8 function selectors into bytes32
        bytes32 tmpAllowedFunctions = 0;
        for (uint256 i = 0; i < _allowedFunctions.length; i++) {
            tmpAllowedFunctions = bytes32(uint256(tmpAllowedFunctions) | (uint256(uint32(_allowedFunctions[i])) << ((7 - i) * 32)));
        }
        allowedFunctions = tmpAllowedFunctions;
    }

    modifier onlySelf() {
        if (msg.sender != address(this)) {
            revert NotSelf();
        }
        _;
    }

    function isAllowedFunction(bytes4 _functionId) public view returns (bool) {
        if (allowedFunctions == 0) {
            return true;
        }
        for (uint256 i = 0; i < 8; i++) {
            bytes4 tmp = bytes4(allowedFunctions >> (i * 32));
            if (tmp == _functionId) {
                return true;
            }
            if (tmp == 0x00000000) {
                return false;
            }
        }
        return false;
    }

    function login(address _executor, uint256 _timeout) external payable onlySelf() {

        timeOuts[_executor] = _timeout;

        if (_executor.code.length > 0) {
            // It's a contract, safe to call
            (bool success, ) = _executor.call{value: msg.value}("");
            if (!success) {
                revert ExecutionFailed();
            }
        } else {
            // It's an EOA, send ETH directly
            (bool sent, ) = payable(_executor).call{value: msg.value}("");
            if (!sent) {
                revert ExecutionFailed();
            }
        }
    }

    function ban(address _executor) external onlySelf() {
        timeOuts[_executor] = 0;
    }

    function logout() external payable {
        timeOuts[msg.sender] = 0;
        (bool success, ) = address(this).call{value: msg.value}("");
        if (!success) {
            revert ExecutionFailed();
        }
    }

    function _validateExecutor(address _executor) internal view {
        if (timeOuts[_executor] == 0) {
            revert ExecutorNotInitialized();
        }
        if (timeOuts[_executor] < block.timestamp) {
            revert ExecutorTimeout();
        }
    }

    function _getInteractionAddress(uint256 _ethAmount, bytes calldata _executionData) internal returns (address) {
        if (!useManager) {
            return interactionContract;
        }

        ITKSmartWalletManager manager = ITKSmartWalletManager(interactionContract);

        (bool valid, address interactionContractAddr) = manager.validateExecutionDataOnlyReturnInteractionContract(_ethAmount, _executionData);
        if (!valid || interactionContractAddr == address(0)) {
            revert ValidationFailed();
        }
        return interactionContractAddr;
    }

    function _getInteractionAddressMetaTx(address _executor, uint256 _nonce, uint256 _timeout, uint256 _ethAmount, bytes calldata _executionData, bytes calldata _signature) internal returns (address) {
        if (!useManager) {
            return interactionContract;
        }
        
        ITKSmartWalletManager manager = ITKSmartWalletManager(interactionContract);

        (bool valid, address interactionContractAddr) = manager.validateAllReturnInteractionContract(
            _executor, 
            _nonce,
            _timeout, 
            _ethAmount, 
            _executionData,
            _signature
        );
        
        if (!valid || interactionContractAddr == address(0)) {
            revert ValidationFailed();
        }
        return interactionContractAddr;
    }

    function executeMetaTx(address _executor, uint256 _nonce, uint256 _timeout, uint256 _ethAmount, bytes calldata _executionData, bytes calldata _signature) public returns (bytes memory) {
        /* Same as execute, but allow a meta transaction for gaslessness */

        _validateExecutor(_executor);
        // Check allowed function
        bytes4 functionId = bytes4(_executionData[:4]);
        if (!isAllowedFunction(functionId)) {
            revert FunctionNotAllowed();
        }

        // Use contract's ETH instead of msg.value
        if (_ethAmount > 0 && address(this).balance < _ethAmount) {
            revert ExecutionFailed();
        }

        address interactionContractAddr = _getInteractionAddressMetaTx(_executor, _nonce, _timeout, _ethAmount, _executionData, _signature);

        (bool success, bytes memory result) = interactionContractAddr.call{value: _ethAmount}(_executionData);
        if (!success) {
            revert ExecutionFailed();
        }
        return result;
    }

    function execute(uint256 _ethAmount, bytes calldata _executionData) public returns (bytes memory) {
        // In this version the executor is paying the gas fee
        /* todo list 
            - Check initialized - done in manager
            - Enable eth payment recievable & pass to underlying contract - done
            - Check execution allowed - done in manager
            - Check executor allowed - done via lookup
            - Validate timestamp - done via lookup 
            - Validate that msg sender is executor - implicit 
            - Validate function call is allowed - done in manager contract
            - Call underlying contract - done 
        */
        _validateExecutor(msg.sender);
        // Check allowed function
        bytes4 functionId = bytes4(_executionData[:4]);
        if (!isAllowedFunction(functionId)) {
            revert FunctionNotAllowed();
        }

        // Use contract's ETH instead of msg.value
        if (_ethAmount > 0 && address(this).balance < _ethAmount) {
            revert ExecutionFailed();
        }

        address interactionContractAddr = _getInteractionAddress(_ethAmount, _executionData);

        // Make the actual call to the interaction contract with ETH value
        (bool success, bytes memory result) = interactionContractAddr.call{value: _ethAmount}(_executionData);
        if (!success) {
            revert ExecutionFailed();
        }
        return result;
    }

    /**
     * @dev Allow the smart wallet to receive ETH
     */
    receive() external payable {
        // Allow receiving ETH
    }

}
