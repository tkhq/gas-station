// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ITKSmartWalletManager} from "./ITKSmartWalletManager.sol";

contract BasicTKSmartWallet {

    error ExecutionNotAllowed();
    error FunctionNotAllowed();
    error ExecutionFailed();
    error ExecutorBanned();
    error ValidationFailed();
    error NotSelf();
    error ExecutorNotInitialized();
    error ExecutorTimeout();

    address public immutable managementContract; 

    mapping(address => uint256) public timeOuts;

    constructor(
        address _manager
    ) {
        managementContract = _manager;
    }

    modifier onlySelf() {
        if (msg.sender != address(this)) {
            revert NotSelf();
        }
        _;
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

    function executeMetaTx(address _executor, uint256 _nonce, uint256 _timeout, uint256 _ethAmount, bytes calldata _executionData, bytes calldata _signature) public returns (bytes memory) {
        /* Same as execute, but allow a meta transaction for gaslessness */

        _validateExecutor(_executor);
        ITKSmartWalletManager manager = ITKSmartWalletManager(managementContract);

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

        // Use contract's ETH instead of msg.value
        if (_ethAmount > 0 && address(this).balance < _ethAmount) {
            revert ExecutionFailed();
        }

        (bool success, bytes memory result) = interactionContractAddr.call{value: _ethAmount}(_executionData);
        if (!success) {
            revert ExecutionFailed();
        }
        return result;
    }

    function execute(uint256 _ethAmount, bytes memory _executionData) public returns (bytes memory) {
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
        ITKSmartWalletManager manager = ITKSmartWalletManager(managementContract);

        (bool valid, address interactionContractAddr) = manager.validateExecutionDataOnlyReturnInteractionContract(_ethAmount, _executionData);
        if (!valid || interactionContractAddr == address(0)) {
            revert ValidationFailed();
        }

        // Use contract's ETH instead of msg.value
        if (_ethAmount > 0 && address(this).balance < _ethAmount) {
            revert ExecutionFailed();
        }

        // Make the actual call to the interaction contract with ETH value
        (bool success, bytes memory result) = interactionContractAddr.call{value: _ethAmount}(_executionData);
        if (!success) {
            revert ExecutionFailed();
        }
        return result;
    }

    function getNonce(address _executor) external view returns (uint256) {
        return ITKSmartWalletManager(managementContract).getNonce(msg.sender, _executor);
    }

    /**
     * @dev Allow the smart wallet to receive ETH
     */
    receive() external payable {
        // Allow receiving ETH
    }

}
