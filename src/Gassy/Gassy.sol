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

contract Gassy is IERC1155Receiver, IERC721Receiver {

    address public immutable paymaster;
    uint256 public nonce;

    // note: This should not be a clonable proxy contract since it needs the state variables to be part of the immutable variables (bytecode)
    constructor(
        address _paymaster
    ) {
        paymaster = _paymaster;
    }
    /* External functions */

    function execute(uint256 _nonce, address _outContract, uint256 _ethAmount, bytes calldata _executionData) external returns (bool, bytes memory) {
        if (msg.sender == paymaster) {
            if (_nonce == nonce) {
                ++nonce;
                (bool success, bytes memory result) = _outContract.call{value: _ethAmount}(_executionData);

                if (success) {
                    return (success, result);
                }
                assembly { revert(0, 0) } // ExecutionFailed
            }
            assembly { revert(0, 2) } // InvalidNonce
        }
        assembly { revert(0, 1) } // NotPaymaster
    }
/*
    function execute(address _outContract, bytes calldata _executionData) external returns (bool, bytes memory) {
        if (msg.sender == paymaster) {
            (bool success, bytes memory result) = _outContract.call(_executionData);

            if (success) {
                return (success, result);
            }
            assembly { revert(0, 0) } // ExecutionFailed
        }
        assembly { revert(0, 1) } // NotPaymaster
        if (msg.sender == paymaster) {
            assembly {
            // Make the call (no ETH value)
            let success := call(gas(), _outContract, 0, add(_executionData.offset, 0x20), _executionData.length, 0, 0)
            
            if iszero(success) {
               // revert(0, 1) // ExecutionFailed
            }
            
            // Handle returndata
            let returndataSize := returndatasize()
            let returndataPtr := mload(0x40) // Get free memory pointer
            
            // Copy returndata to memory
            returndatacopy(returndataPtr, 0, returndataSize)
            
            // Store success (true) at memory position 0
            mstore(0, 1)
            
            // Store returndata size at memory position 0x20
            mstore(0x20, returndataSize)
            
            // Store returndata pointer at memory position 0x40
            mstore(0x40, returndataPtr)
            
            // Update free memory pointer
            mstore(0x40, add(returndataPtr, returndataSize))
            
            // Return (success, returndata)
            return(0, add(0x40, returndataSize))
            }
        }
        assembly { revert(0, 2) } // NotPaymaster
        
    }
    */

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
