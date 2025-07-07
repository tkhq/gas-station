// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ITKSmartWalletManager} from "./ITKSmartWalletManager.sol";

contract BasicTKSmartWallet {

    error ExecutionNotAllowed();
    error FunctionNotAllowed();
    error ExecutionFailed();
    error ExecutorBanned();
    error ValidationFailed();

    address public immutable managementContract; 

    constructor(
        address _manager
    ) {
        managementContract = _manager;
    }
    
    function execute(address _fundingEOA, uint256 _timeout, bytes calldata _signature, bytes memory _executionData) external returns (bytes memory) {
        /* todo list 
            - Check initialized
            - Enable eth payment recievable & pass to underlying contract 
            - Check execution allowed - done
            - Check executor allowed
            - Validate if signature has been signed by fundingEOA - done
            - Validate timestamp - done 
            - Validate that msg sender is executor - implicit in 712 - done 
            - Validate function call is allowed - done 
            - Sponsor gas from _fundingEOA (or elsewhere) 
            - Spoof message sender as _fundingEOA - done 
            - Call underlying contract - done 
        */
        ITKSmartWalletManager manager = ITKSmartWalletManager(managementContract);

        (bool valid, address interactionContractAddr) = manager.validateAllReturnInteractionContract(_fundingEOA, msg.sender, _timeout, _signature, _executionData);
        if (!valid || interactionContractAddr == address(0)) {
            revert ValidationFailed();
        }

        // Make the actual call to the interaction contract
        (bool success, bytes memory result) = interactionContractAddr.call(_executionData);
        if (!success) {
            revert ExecutionFailed();
        }
        return result;
    }

}
