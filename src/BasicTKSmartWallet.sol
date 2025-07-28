// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ITKSmartWalletManager} from "./Interfaces/ITKSmartWalletManager.sol";
import {ITKSmartWallet} from "./Interfaces/ITKSmartWallet.sol";
import {EIP712} from "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

import "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";


contract BasicTKSmartWallet is ITKSmartWallet, EIP712, IERC1155Receiver, IERC721Receiver {

    error FunctionNotAllowed();
    error ExecutionFailed();
    error ExecutorBanned();
    error ValidationFailed();
    error NotSelf();
    error ExecutorNotInitialized();
    error ExecutorTimeout();
    error InvalidFunctionId();
    error ZeroAddress();
    error MetaTxNotAllowed();
    error TooManyFunctions();
    error InvalidSignature();
    error InvalidNonce();

    address public immutable interactionContract; 

    bool public immutable useAllowedFunctions;
    
    bytes32 public immutable allowedFunctions;
    
    // EIP-712 constants
    bytes32 public constant TK_SMART_WALLET_EXECUTE_TYPEHASH =
        keccak256("TKSmartWalletExecute(address executor, uint256 nonce, uint256 timeout, uint256 ethAmount, bytes executionData)");
    
    // Packed struct for wallet state (64 bits timeout + 32 bits nonce + 160 bits executor = 256 bits, fits in 256-bit slot)
    struct State {
        uint64 timeout;
        uint32 nonce;
        address executor;
    }
    State public state;

    // note: This should not be a clonable proxy contract since it needs the state variables to be part of the immutable variables (bytecode)
    constructor(
        address _interactionContract,
        bytes4[] memory _allowedFunctions
    ) EIP712("TKSmartWallet", "1.0.0") {
        if (_interactionContract == address(0)) {
            revert ZeroAddress();
        }
        if (_allowedFunctions.length > 8) {
            revert TooManyFunctions();
        }
        interactionContract = _interactionContract;
        
        useAllowedFunctions = _allowedFunctions.length > 0;
        // Pack up to 8 function selectors into bytes32
        if (useAllowedFunctions) {
            bytes32 tmpAllowedFunctions = 0;
            for (uint256 i = 0; i < _allowedFunctions.length; i++) {
                tmpAllowedFunctions = bytes32(uint256(tmpAllowedFunctions) | (uint256(uint32(_allowedFunctions[i])) << ((7 - i) * 32)));
            }
            allowedFunctions = tmpAllowedFunctions;
        } else {
            allowedFunctions = 0;
        }
    }

    /* Internal functions */
    
    function _isAllowedFunction(bytes4 _functionId) internal view {
        if (!useAllowedFunctions) {
            return; // Allow
        }
        if (allowedFunctions == 0) {
            return; // Allow
        }
        for (uint256 i = 0; i < 8; i++) {
            bytes4 tmp = bytes4(allowedFunctions >> (i * 32));
            if (tmp == _functionId) {
                return; // Allow
            }
            if (tmp == 0x00000000) {
                revert FunctionNotAllowed();
            }
        }
        revert FunctionNotAllowed();
    }

    function _validateExecutor(address _executor) internal view {
        uint64 timeout = state.timeout;
        if (state.executor != _executor || timeout == 0) {
            revert ExecutorNotInitialized();
        }
        if (timeout < block.timestamp) {
            revert ExecutorTimeout();
        }
    }
    
    /* External functions */

    function getNonce() external view returns (uint256) {
        return state.nonce;
    }

    function login(address _executor, uint64 _timeout) external {
        if (msg.sender != address(this)) {
            revert NotSelf();
        }

        state.executor = _executor;
        state.timeout = _timeout;
    }

    function logout() external {
        if (msg.sender != address(this) && msg.sender != state.executor) {
            revert NotSelf();
        }
        state.executor = address(0); // don't touch nonce for security purposes and don't touch timeout so to save gas on next write 
    }

    function executeMetaTx(address _executor, uint256 _nonce, uint256 _timeout, uint256 _ethAmount, bytes calldata _executionData, bytes calldata _signature) public returns (bool success, bytes memory result) {
        /* Same as execute, but allow a meta transaction for gaslessness */

        _validateExecutor(_executor);
        // Check allowed function
        bytes4 functionId = bytes4(_executionData[:4]);
        _isAllowedFunction(functionId);

        // Use contract's ETH instead of msg.value
        if (_ethAmount > 0 && address(this).balance < _ethAmount) {
            revert ExecutionFailed();
        }

        // Make the actual call to the interaction contract with ETH value
        // Handle meta transaction validation directly in the wallet
        if (block.timestamp > _timeout) {
            revert ExecutorTimeout();
        }

        uint32 currentNonce = state.nonce;
        if (currentNonce != _nonce) {
            revert InvalidNonce();
        }
        state.nonce = currentNonce + 1;

        bytes32 hash = _hashTypedDataV4(keccak256(abi.encode(TK_SMART_WALLET_EXECUTE_TYPEHASH, _executor, _nonce, _timeout, _ethAmount, _executionData)));
        address signer = ECDSA.recover(hash, _signature);
        
        if (signer != _executor) {
            revert InvalidSignature();
        }

        (success, result) = interactionContract.call{value: _ethAmount}(_executionData);
        if (!success) {
            revert ExecutionFailed();
        }
        return (success, result);

    }

    function execute(uint256 _ethAmount, bytes calldata _executionData) public returns (bool success, bytes memory result) {
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
        _isAllowedFunction(functionId);

        // Use contract's ETH instead of msg.value
        if (_ethAmount > 0 && address(this).balance < _ethAmount) {
            revert ExecutionFailed();
        }

        // Make the actual call to the interaction contract with ETH value
        (success, result) = interactionContract.call{value: _ethAmount}(_executionData);

        if (!success) {
            revert ExecutionFailed();
        }
        return (success, result);

    }

    /**
     * @dev Allow the smart wallet to receive ETH and ERC1155/721 tokens
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
        return this.onERC721Received.selector;
    }

    // ERC1155 Receiver function
    function onERC1155Received(
        address, /* operator */
        address, /* from */
        uint256, /* id */
        uint256, /* value */
        bytes calldata /* data */
    ) external pure override returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    // ERC1155 Batch Receiver function
    function onERC1155BatchReceived(
        address, /* operator */
        address, /* from */
        uint256[] calldata, /* ids */
        uint256[] calldata, /* values */
        bytes calldata /* data */
    ) external pure override returns (bytes4) {
        return this.onERC1155BatchReceived.selector;
    }


}
