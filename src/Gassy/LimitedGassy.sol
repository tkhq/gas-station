// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

// Minimal interfaces defined inline to save gas
interface IERC721Receiver {
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data) external pure returns (bytes4);
}

interface IERC1155Receiver {
    function onERC1155Received(address operator, address from, uint256 id, uint256 value, bytes calldata data) external pure returns (bytes4);
    function onERC1155BatchReceived(address operator, address from, uint256[] calldata ids, uint256[] calldata values, bytes calldata data) external pure returns (bytes4);
}

contract LimitedGassy is IERC1155Receiver, IERC721Receiver {

    address public immutable paymaster;
    address public immutable presetOutContract;

    // note: This should not be a clonable proxy contract since it needs the state variables to be part of the immutable variables (bytecode)
    constructor(
        address _paymaster,
        address _presetOutContract
    ) {
        paymaster = _paymaster;
        presetOutContract = _presetOutContract;
    }
    /* External functions */

    function execute(uint256 _ethAmount, bytes calldata _executionData) external returns (bool, bytes memory) {
        assembly {
            if and(gt(_ethAmount, 0), lt(selfbalance(), _ethAmount)) {
                revert(0, 0) // Insufficient balance
            }
        }
        
        if (msg.sender == paymaster) {
            (bool success, bytes memory result) = presetOutContract.call{value: _ethAmount}(_executionData);

            if (success) {
                return (success, result);
            }
            assembly { revert(0, 1) } // ExecutionFailed
        }
        assembly { revert(0, 2) } // NotPaymaster
    }

    function execute(bytes calldata _executionData) external returns (bool, bytes memory) {
        
        if (msg.sender == paymaster) {
            (bool success, bytes memory result) = presetOutContract.call(_executionData);

            if (success) {
                return (success, result);
            }
            assembly { revert(0, 1) } // ExecutionFailed
        }
        assembly { revert(0, 2) } // NotPaymaster
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
        assembly {
            mstore(0, 0x150b7a02)
            return(0, 4)
        }
    }

    // ERC1155 Receiver function
    function onERC1155Received(
        address, /* operator */
        address, /* from */
        uint256, /* id */
        uint256, /* value */
        bytes calldata /* data */
    ) external pure override returns (bytes4) {
        assembly {
            mstore(0, 0xf23a6e61)
            return(0, 4)
        }
    }

    // ERC1155 Batch Receiver function
    function onERC1155BatchReceived(
        address, /* operator */
        address, /* from */
        uint256[] calldata, /* ids */
        uint256[] calldata, /* values */
        bytes calldata /* data */
    ) external pure override returns (bytes4) {
        assembly {
            mstore(0, 0xbc197c81)
            return(0, 4)
        }
    }

}
