// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IBatchExecution} from "./IBatchExecution.sol";

// Minimal interfaces defined inline to save gas
interface IERC721Receiver {
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data)
        external
        pure
        returns (bytes4);
}

interface IERC1155Receiver {
    function onERC1155Received(address operator, address from, uint256 id, uint256 value, bytes calldata data)
        external
        pure
        returns (bytes4);
    function onERC1155BatchReceived(
        address operator,
        address from,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    ) external pure returns (bytes4);
}

contract TKGasDelegate is IERC1155Receiver, IERC721Receiver {
    // Custom errors
    error ExecutionFailed();
    error NotPaymaster();

    address public immutable paymaster;

    // note: This should not be a clonable proxy contract since it needs the state variables to be part of the immutable variables (bytecode)
    constructor(address _paymaster) {
        paymaster = _paymaster;
    }

    /* External functions */

    function execute(address _outContract, bytes calldata _executionData) external returns (bool, bytes memory) {
        if (msg.sender == paymaster) {
            (bool success, bytes memory result) = _outContract.call(_executionData);

            if (success) {
                return (success, result);
            }
            revert ExecutionFailed();
        }
        revert NotPaymaster();
    }

    function execute(address _outContract, uint256 _ethAmount, bytes calldata _executionData)
        external
        returns (bool, bytes memory)
    {
        if (msg.sender == paymaster) {
            (bool success, bytes memory result) = _outContract.call{value: _ethAmount}(_executionData);

            if (success) {
                return (success, result);
            }
            revert ExecutionFailed();
        }
        revert NotPaymaster();
    }

    function executeBatch(IBatchExecution.Execution[] calldata _executions) external returns (bool, bytes[] memory) {
        if (msg.sender != paymaster) revert NotPaymaster();
        
        bytes[] memory results = new bytes[](_executions.length);
        
        for (uint256 i = 0; i < _executions.length;) {
            uint256 ethAmount = _executions[i].ethAmount;
            address outputContract = _executions[i].outputContract;
            
            (bool success, bytes memory result) = ethAmount == 0 
                ? outputContract.call(_executions[i].arguments)
                : outputContract.call{value: ethAmount}(_executions[i].arguments);
                
            results[i] = result;
            if (!success) revert ExecutionFailed();
            
            unchecked { ++i; }
        }
        
        return (true, results);
    }

    /**
     * @dev Needed to allow the smart wallet to receive ETH and ERC1155/721 tokens
     */
    receive() external payable {
        // Allow receiving ETH
    }

    // ERC721 Receiver function
    function onERC721Received(
        address, /* operator */
        address, /* from */
        uint256, /* tokenId */
        bytes calldata /* data */
    ) external pure override returns (bytes4) {
        return 0x150b7a02;
    }

    // ERC1155 Receiver function
    function onERC1155Received(
        address, /* operator */
        address, /* from */
        uint256, /* id */
        uint256, /* value */
        bytes calldata /* data */
    ) external pure override returns (bytes4) {
        return 0xf23a6e61;
    }

    // ERC1155 Batch Receiver function
    function onERC1155BatchReceived(
        address, /* operator */
        address, /* from */
        uint256[] calldata, /* ids */
        uint256[] calldata, /* values */
        bytes calldata /* data */
    ) external pure override returns (bytes4) {
        return 0xbc197c81;
    }
}
