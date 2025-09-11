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

contract Gassy is IERC1155Receiver, IERC721Receiver {
    address public immutable paymaster;

    uint128 public nonce;
    uint128 public timeboxedCounter;

    // note: This should not be a clonable proxy contract since it needs the state variables to be part of the immutable variables (bytecode)
    constructor(address _paymaster) {
        paymaster = _paymaster;
    }

    /* External functions */

    function execute(uint128 _nonce, address _outContract, bytes calldata _executionData)
        external
        returns (bool, bytes memory)
    {
        if (msg.sender == paymaster) {
            if (_nonce == nonce) {
                ++nonce;
                (bool success, bytes memory result) = _outContract.call(_executionData);

                if (success) {
                    return (success, result);
                }
                assembly {
                    revert(0, 0)
                } // ExecutionFailed
            }
            assembly {
                revert(0, 1)
            } // InvalidNonce
        }
        assembly {
            revert(0, 2)
        } // NotPaymaster
    }

    function execute(uint128 _nonce, address _outContract, uint256 _ethAmount, bytes calldata _executionData)
        external
        returns (bool, bytes memory)
    {
        if (msg.sender == paymaster) {
            if (_nonce == nonce) {
                ++nonce;
                (bool success, bytes memory result) = _outContract.call{value: _ethAmount}(_executionData);

                if (success) {
                    return (success, result);
                }
                assembly {
                    revert(0, 0)
                } // ExecutionFailed
            }
            assembly {
                revert(0, 1)
            } // InvalidNonce
        }
        assembly {
            revert(0, 2)
        } // NotPaymaster
    }

    function executeBatch(uint128 _nonce, IBatchExecution.Execution[] calldata _executions)
        external
        returns (bool, bytes[] memory)
    {
        if (msg.sender == paymaster) {
            if (_nonce == nonce) {
                ++nonce;

                bytes[] memory results = new bytes[](_executions.length);

                for (uint8 i = 0; i < _executions.length;) {
                    if (_executions[i].ethAmount == 0) {
                        (bool success, bytes memory result) =
                            _executions[i].outputContract.call(_executions[i].arguments);
                        results[i] = result;
                        if (!success) {
                            assembly {
                                revert(0, 0)
                            } // ExecutionFailed
                        }
                    } else {
                        (bool success, bytes memory result) = _executions[i].outputContract.call{
                            value: _executions[i].ethAmount
                        }(_executions[i].arguments);
                        results[i] = result;
                        if (!success) {
                            assembly {
                                revert(0, 0)
                            } // ExecutionFailed
                        }
                    }
                    unchecked {
                        ++i;
                    }
                }

                return (true, results);
            }
            assembly {
                revert(0, 1)
            } // InvalidNonce
        }
        assembly {
            revert(0, 2)
        } // NotPaymaster
    }

    function burnNonce(uint128 _nonce) external {
        if (msg.sender == paymaster || (msg.sender == address(this) && tx.origin == address(this))) {
            if (_nonce == nonce) {
                ++nonce;
                return;
            }
            assembly {
                revert(0, 1)
            } // InvalidNonce
        }
        assembly {
            revert(0, 2)
        } // NotPaymaster
    }

    function executeTimeboxed(
        uint128 _counter,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _executionData
    ) external returns (bool, bytes memory) {
        if (msg.sender == paymaster) {
            if (_counter == timeboxedCounter) {
                (bool success, bytes memory result) = _outputContract.call{value: _ethAmount}(_executionData);

                if (success) {
                    return (success, result);
                }
                assembly {
                    revert(0, 0)
                } // ExecutionFailed
            }
            assembly {
                revert(0, 1)
            } // InvalidNonce
        }
        assembly {
            revert(0, 2)
        } // NotPaymaster
    }

    function executeBatchTimeboxed(uint128 _counter, IBatchExecution.Execution[] calldata _executions)
        external
        returns (bool, bytes[] memory)
    {
        if (msg.sender == paymaster) {
            if (_counter == timeboxedCounter) {
                bytes[] memory results = new bytes[](_executions.length);

                for (uint8 i = 0; i < _executions.length;) {
                    if (_executions[i].ethAmount == 0) {
                        (bool success, bytes memory result) =
                            _executions[i].outputContract.call(_executions[i].arguments);
                        results[i] = result;
                        if (!success) {
                            assembly {
                                revert(0, 0)
                            } // ExecutionFailed
                        }
                    } else {
                        (bool success, bytes memory result) = _executions[i].outputContract.call{
                            value: _executions[i].ethAmount
                        }(_executions[i].arguments);
                        results[i] = result;
                        if (!success) {
                            assembly {
                                revert(0, 0)
                            } // ExecutionFailed
                        }
                    }
                    unchecked {
                        ++i;
                    }
                }

                return (true, results);
            }
            assembly {
                revert(0, 1)
            } // InvalidNonce
        }
        assembly {
            revert(0, 2)
        } // NotPaymaster
    }

    function burnTimeboxedCounter(uint128 _counter) external {
        if (msg.sender == paymaster || (msg.sender == address(this) && tx.origin == address(this))) {
            if (timeboxedCounter == _counter) {
                ++timeboxedCounter;
                return;
            }
            assembly {
                revert(0, 1)
            } // InvalidNonce
        }
        assembly {
            revert(0, 2)
        } // NotPaymaster
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
