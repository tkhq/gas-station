// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";


contract Gassy is IERC1155Receiver, IERC721Receiver {

    error NotPaymaster();
    error ExecutionFailed();

    address public immutable paymaster;
    
    // Constants for receiver function selectors to save gas
    bytes4 private constant ERC721_RECEIVED = 0x150b7a02;
    bytes4 private constant ERC1155_RECEIVED = 0xf23a6e61;
    bytes4 private constant ERC1155_BATCH_RECEIVED = 0xbc197c81; 

    // note: This should not be a clonable proxy contract since it needs the state variables to be part of the immutable variables (bytecode)
    constructor(
        address _paymaster
    ) {
        paymaster = _paymaster; 
    }

    /* Internal functions */

    function _validateExecutor(address _executor) internal view {
        if (_executor != paymaster) {
            revert NotPaymaster();
        }
    }
    
    /* External functions */

    function execute(address _outContract, uint256 _ethAmount, bytes calldata _executionData) external returns (bool success, bytes memory result) {
        // In this version the executor is paying the gas fee
        _validateExecutor(msg.sender);
        // Use contract's ETH instead of msg.value
        if (_ethAmount > 0 && address(this).balance < _ethAmount) {
            revert ExecutionFailed();
        }

        (success, result) = _outContract.call{value: _ethAmount}(_executionData);

        if (!success) {
            revert ExecutionFailed();
        }
        return (success, result);

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
        return ERC721_RECEIVED;
    }

    // ERC1155 Receiver function
    function onERC1155Received(
        address, /* operator */
        address, /* from */
        uint256, /* id */
        uint256, /* value */
        bytes calldata /* data */
    ) external pure override returns (bytes4) {
        return ERC1155_RECEIVED;
    }

    // ERC1155 Batch Receiver function
    function onERC1155BatchReceived(
        address, /* operator */
        address, /* from */
        uint256[] calldata, /* ids */
        uint256[] calldata, /* values */
        bytes calldata /* data */
    ) external pure override returns (bytes4) {
        return ERC1155_BATCH_RECEIVED;
    }

}
