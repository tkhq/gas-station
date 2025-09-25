// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ECDSA} from "solady/utils/ECDSA.sol";
import {EIP712} from "solady/utils/EIP712.sol";

// Shared interface for batch execution structures
interface IBatchExecution {
    struct Execution {
        address outputContract;
        uint256 ethAmount;
        bytes arguments;
    }
}

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

contract TKGasStation is EIP712, IERC1155Receiver, IERC721Receiver {
    // Custom errors
    error BatchSizeExceeded();
    error DeadlineExceeded();
    error InvalidOutputContract();
    error InvalidNonce();
    error InvalidCounter();
    error NotSelf();
    error ExecutionFailed(); 

    // EIP712 type hashes (precomputed for gas optimization)
    bytes32 private constant EXECUTION_TYPEHASH = 0xcd5f5d65a387f188fe5c0c9265c7e7ec501fa0b0ee45ad769c119694cac5d895;
    // Original: keccak256("Execution(uint128 nonce,address outputContract,uint256 ethAmount,bytes arguments)")

    bytes32 private constant BATCH_EXECUTION_TYPEHASH =
        0xf73c9911df56a9710eecfac385726c4fd80b78c1f52622e0a468473af71dccc8;
    // Original: keccak256("BatchExecution(uint128 nonce,Execution[] executions)Execution(address outputContract,uint256 ethAmount,bytes arguments)")

    bytes32 private constant BURN_NONCE_TYPEHASH = 0x1abb8920e48045adda3ed0ce4be4357be95d4aa21af287280f532fc031584bda;
    // Original: keccak256("BurnNonce(uint128 nonce)")

    bytes32 private constant TIMEBOXED_EXECUTION_TYPEHASH =
        0x572542ff5f8730cc3585cab0d01b4696eadf4bd390c1dbbaa4467a76cb6f95bf;
    // Original: keccak256("TimeboxedExecution(uint128 counter,uint128 deadline,address sender,address outputContract)")

    bytes32 private constant ARBITRARY_TIMEBOXED_EXECUTION_TYPEHASH =
        0xc0d6acc328e7656b4ab6234f5efb8bc56b83d5b67d829ae64ea7ebe07f0968ee;
    // Original: keccak256("ArbitraryTimeboxedExecution(uint128 counter,uint128 deadline,address sender)")

    bytes32 private constant BURN_TIMEBOXED_COUNTER_TYPEHASH =
        0x96d439a73c6f9c1949a24d89d523289f8d4857543fa33be656cc2a3037807baa;
    // Original: keccak256("BurnTimeboxedCounter(uint128 counter,address sender)")

    // Maximum batch size to prevent griefing attacks
    uint256 public constant MAX_BATCH_SIZE = 50;

    uint128 public timeboxedCounter;
    uint128 public nonce;

    constructor() EIP712() {
    }


    function _domainNameAndVersion()
        internal
        pure
        override
        returns (string memory name, string memory version)
    {
        name = "TKGasStation";
        version = "1";
    }

    function hashExecution(uint128 _nonce, address _outputContract, uint256 _ethAmount, bytes calldata _arguments)
        external
        view
        returns (bytes32)
    {
        bytes32 argsHash = keccak256(_arguments);
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _nonce)
            mstore(add(ptr, 0x40), _outputContract)
            mstore(add(ptr, 0x60), _ethAmount)
            mstore(add(ptr, 0x80), argsHash)
            hash := keccak256(ptr, 0xa0)
        }
        return _hashTypedData(hash);
    }

    function execute(uint128 _nonce, address _outputContract, bytes calldata _arguments, bytes calldata _signature)
        external
        returns (bool, bytes memory)
    {
        bytes32 argsHash = keccak256(_arguments);
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _nonce)
            mstore(add(ptr, 0x40), _outputContract)
            mstore(add(ptr, 0x60), 0) // ethAmount = 0
            mstore(add(ptr, 0x80), argsHash)
            hash := keccak256(ptr, 0xa0)
        }
        hash = _hashTypedData(hash);
        
        if (ECDSA.recover(hash, _signature) != address(this)) {
            revert NotSelf();
        }

        if (_nonce == nonce) {
            unchecked {
                nonce = nonce + 1;
            }
            (bool success, bytes memory result) = _outputContract.call(_arguments);

            if (success) {
                return (success, result);
            }
            revert ExecutionFailed();
        }
        revert InvalidNonce();
    }

    function execute(
        uint128 _nonce,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments,
        bytes calldata _signature
    ) external returns (bool, bytes memory) {
        bytes32 argsHash = keccak256(_arguments);
        bytes32 hash; // all this assembly to avoid using abi.encode
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _nonce)
            mstore(add(ptr, 0x40), _outputContract)
            mstore(add(ptr, 0x60), _ethAmount)
            mstore(add(ptr, 0x80), argsHash)
            hash := keccak256(ptr, 0xa0)
        }
        hash = _hashTypedData(hash);
        
        if (ECDSA.recover(hash, _signature) != address(this)) {
            revert NotSelf();
        }
        
        uint128 currentNonce = nonce;
        
        if (_nonce == currentNonce) {
            unchecked {
                nonce = currentNonce + 1;
            }
            (bool success, bytes memory result) = _outputContract.call{value: _ethAmount}(_arguments);

            if (success) {
                return (success, result);
            }
            revert ExecutionFailed();
        }
        revert InvalidNonce();
    }

    function hashBurnNonce(uint128 _nonce) external view returns (bytes32) {
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, BURN_NONCE_TYPEHASH)
            mstore(add(ptr, 0x20), _nonce)
            hash := keccak256(ptr, 0x40)
        }
        return _hashTypedData(hash);
    }

    function burnNonce(uint128 _nonce, bytes calldata _signature) external {
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) 
            mstore(ptr, BURN_NONCE_TYPEHASH)
            mstore(add(ptr, 0x20), _nonce)
            hash := keccak256(ptr, 0x40)
        }
        hash = _hashTypedData(hash);
        
        if (_nonce != nonce) {
            revert InvalidNonce();
        }
        if (ECDSA.recover(hash, _signature) != address(this)) {
            revert NotSelf();
        }
        unchecked {
            ++nonce;
        }
    }

    function burnNonce() external {
        if (msg.sender != address(this) || msg.sender != tx.origin) {
            revert NotSelf();
        }
        unchecked {
            ++nonce;
        }
    }

    /* Timeboxed execution */

    function hashTimeboxedExecution(uint128 _counter, uint128 _deadline, address _sender, address _outputContract)
        external
        view
        returns (bytes32)
    {
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, TIMEBOXED_EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _counter)
            mstore(add(ptr, 0x40), _deadline)
            mstore(add(ptr, 0x60), _sender)
            mstore(add(ptr, 0x80), _outputContract)
            hash := keccak256(ptr, 0xa0)
        }
        return _hashTypedData(hash);
    }

    function hashArbitraryTimeboxedExecution(uint128 _counter, uint128 _deadline, address _sender)
        external
        view
        returns (bytes32)
    {
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, ARBITRARY_TIMEBOXED_EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _counter)
            mstore(add(ptr, 0x40), _deadline)
            mstore(add(ptr, 0x60), _sender)
            hash := keccak256(ptr, 0x80)
        }
        return _hashTypedData(hash);
    }

    function hashBurnTimeboxedCounter(uint128 _counter, address _sender) external view returns (bytes32) {
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, BURN_TIMEBOXED_COUNTER_TYPEHASH)
            mstore(add(ptr, 0x20), _counter)
            mstore(add(ptr, 0x40), _sender)
            hash := keccak256(ptr, 0x60)
        }
        return _hashTypedData(hash);
    }

    function executeTimeboxed(
        uint128 _counter,
        uint128 _deadline,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments,
        bytes calldata _signature
    ) external returns (bool, bytes memory) {
        // Check if deadline has passed
        if (block.timestamp > _deadline) {
            revert DeadlineExceeded();
        }

        address sender = msg.sender;
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, TIMEBOXED_EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _counter)
            mstore(add(ptr, 0x40), _deadline)
            mstore(add(ptr, 0x60), sender)
            mstore(add(ptr, 0x80), _outputContract)
            hash := keccak256(ptr, 0xa0)
        }
        hash = _hashTypedData(hash);
        
        if (_counter != timeboxedCounter) {
            revert InvalidCounter();
        }
        if (ECDSA.recover(hash, _signature) != address(this)) {
            revert NotSelf();
        }

        (bool success, bytes memory result) = _outputContract.call{value: _ethAmount}(_arguments);

        if (success) {
            return (success, result);
        }
        revert ExecutionFailed();
    }

    function executeTimeboxed(
        uint128 _counter,
        uint128 _deadline,
        address _outputContract,
        bytes calldata _arguments,
        bytes calldata _signature
    ) external returns (bool, bytes memory) {
        // Check if deadline has passed
        if (block.timestamp > _deadline) {
            revert DeadlineExceeded();
        }

        address sender = msg.sender;
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, TIMEBOXED_EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _counter)
            mstore(add(ptr, 0x40), _deadline)
            mstore(add(ptr, 0x60), sender)
            mstore(add(ptr, 0x80), _outputContract)
            hash := keccak256(ptr, 0xa0)
        }
        hash = _hashTypedData(hash);
        
        if (_counter != timeboxedCounter) {
            revert InvalidCounter();
        }
        if (ECDSA.recover(hash, _signature) != address(this)) {
            revert NotSelf();
        }
        // Execute the timeboxed transaction (counter does NOT increment for timeboxed)
        (bool success, bytes memory result) = _outputContract.call(_arguments);

        if (success) {
            return (success, result);
        }
        revert ExecutionFailed();
    }

    function executeBatchTimeboxed(
        uint128 _counter,
        uint128 _deadline,
        address _outputContract,
        IBatchExecution.Execution[] calldata _executions,
        bytes calldata _signature
    ) external returns (bool, bytes[] memory) {
        // Check if deadline has passed
        if (block.timestamp > _deadline) {
            revert DeadlineExceeded();
        }
        // Prevent griefing attacks by limiting batch size
        if (_executions.length > MAX_BATCH_SIZE) {
            revert BatchSizeExceeded();
        }

        address sender = msg.sender;
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, TIMEBOXED_EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _counter)
            mstore(add(ptr, 0x40), _deadline)
            mstore(add(ptr, 0x60), sender)
            mstore(add(ptr, 0x80), _outputContract)
            hash := keccak256(ptr, 0xa0)
        }
        hash = _hashTypedData(hash);
        if (_counter != timeboxedCounter) {
            revert InvalidCounter();
        }
        if (ECDSA.recover(hash, _signature) != address(this)) {
            revert NotSelf();
        }
        for (uint256 i = 0; i < _executions.length;) {
            if (_executions[i].outputContract != _outputContract) {
                revert InvalidOutputContract();
            }
            unchecked {
                ++i;
            }
        }

        // Execute the timeboxed transaction
        uint256 length = _executions.length;
        bytes[] memory results = new bytes[](length);
        
        // Cache array access to avoid repeated calldata reads
        for (uint256 i = 0; i < length;) {
            IBatchExecution.Execution calldata execution = _executions[i];
            uint256 ethAmount = execution.ethAmount;
            address outputContract = execution.outputContract;
            
            (bool success, bytes memory result) = ethAmount == 0 
                ? outputContract.call(execution.arguments)
                : outputContract.call{value: ethAmount}(execution.arguments);
                
            results[i] = result;
            
            if (!success) revert ExecutionFailed();
            
            unchecked { ++i; }
        }
        
        return (true, results);
    }

    function executeTimeboxedArbitrary(
        uint128 _counter,
        uint128 _deadline,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments,
        bytes calldata _signature
    ) external returns (bool, bytes memory) {
        // Check if deadline has passed
        if (block.timestamp > _deadline) {
            revert DeadlineExceeded();
        }

        address sender = msg.sender;
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, ARBITRARY_TIMEBOXED_EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _counter)
            mstore(add(ptr, 0x40), _deadline)
            mstore(add(ptr, 0x60), sender)
            hash := keccak256(ptr, 0x80)
        }
        hash = _hashTypedData(hash);
        if (_counter != timeboxedCounter) {
            revert InvalidCounter();
        }
        if (ECDSA.recover(hash, _signature) != address(this)) {
            revert NotSelf();
        }
        // Execute the timeboxed transaction
        (bool success, bytes memory result) = _outputContract.call{value: _ethAmount}(_arguments);

        if (success) {
            return (success, result);
        }
        revert ExecutionFailed();
    }

    function executeBatchTimeboxedArbitrary(
        uint128 _counter,
        uint128 _deadline,
        IBatchExecution.Execution[] calldata _executions,
        bytes calldata _signature
    ) external returns (bool, bytes[] memory) {
        // Check if deadline has passed
        if (block.timestamp > _deadline) {
            revert DeadlineExceeded();
        }
        // Prevent griefing attacks by limiting batch size
        if (_executions.length > MAX_BATCH_SIZE) {
            revert BatchSizeExceeded();
        }

        address sender = msg.sender;
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, ARBITRARY_TIMEBOXED_EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _counter)
            mstore(add(ptr, 0x40), _deadline)
            mstore(add(ptr, 0x60), sender)
            hash := keccak256(ptr, 0x80)
        }
        hash = _hashTypedData(hash);
        if (_counter != timeboxedCounter) {
            revert InvalidCounter();
        }
        if (ECDSA.recover(hash, _signature) != address(this)) {
            revert NotSelf();
        }
        // Execute the timeboxed transaction
        uint256 length = _executions.length;
        bytes[] memory results = new bytes[](length);
        
        // Cache array access to avoid repeated calldata reads
        for (uint256 i = 0; i < length;) {
            IBatchExecution.Execution calldata execution = _executions[i];
            uint256 ethAmount = execution.ethAmount;
            address outputContract = execution.outputContract;
            
            (bool success, bytes memory result) = ethAmount == 0 
                ? outputContract.call(execution.arguments)
                : outputContract.call{value: ethAmount}(execution.arguments);
                
            results[i] = result;
            
            if (!success) revert ExecutionFailed();
            
            unchecked { ++i; }
        }
        
        return (true, results);
    }

    function burnTimeboxedCounter(uint128 _counter, address _sender, bytes calldata _signature) external {
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, BURN_TIMEBOXED_COUNTER_TYPEHASH)
            mstore(add(ptr, 0x20), _counter)
            mstore(add(ptr, 0x40), _sender)
            hash := keccak256(ptr, 0x60)
        }
        hash = _hashTypedData(hash);
        
        if (_counter != timeboxedCounter) {
            revert InvalidCounter();
        }
        if (ECDSA.recover(hash, _signature) != address(this)) {
            revert NotSelf();
        }
        unchecked {
            ++timeboxedCounter;
        }
    }

    function burnTimeboxedCounter() external {
        if (msg.sender != address(this) || msg.sender != tx.origin) {
            revert NotSelf();
        }
        unchecked {
            ++timeboxedCounter;
        }
    }

    function hashBatchExecution(uint128 _nonce, IBatchExecution.Execution[] calldata _executions)
        external
        view
        returns (bytes32)
    {
        bytes32 executionsHash = keccak256(abi.encode(_executions));
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, BATCH_EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _nonce)
            mstore(add(ptr, 0x40), executionsHash)
            hash := keccak256(ptr, 0x60)
        }
        return _hashTypedData(hash);
    }

    function executeBatch(uint128 _nonce, IBatchExecution.Execution[] calldata _executions, bytes calldata _signature)
        external
        returns (bool, bytes[] memory)
    {
        // Prevent griefing attacks by limiting batch size
        if (_executions.length > MAX_BATCH_SIZE) {
            revert BatchSizeExceeded();
        }

        bytes32 executionsHash = keccak256(abi.encode(_executions));
        bytes32 hash;
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(ptr, BATCH_EXECUTION_TYPEHASH)
            mstore(add(ptr, 0x20), _nonce)
            mstore(add(ptr, 0x40), executionsHash)
            hash := keccak256(ptr, 0x60)
        }
        hash = _hashTypedData(hash);
        if (_nonce != nonce) {
            revert InvalidNonce();
        }
        if (ECDSA.recover(hash, _signature) != address(this)) {
            revert NotSelf();
        }
        unchecked {
            ++nonce;
        }

        uint256 length = _executions.length;
        bytes[] memory results = new bytes[](length);
        
        // Cache array access to avoid repeated calldata reads
        for (uint256 i = 0; i < length;) {
            IBatchExecution.Execution calldata execution = _executions[i];
            uint256 ethAmount = execution.ethAmount;
            address outputContract = execution.outputContract;
            // Do not cash arguments to save on copy costs
            (bool success, bytes memory result) = ethAmount == 0 
                ? outputContract.call(execution.arguments)
                : outputContract.call{value: ethAmount}(execution.arguments);
                
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
