// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {TKGasDelegate} from "./TKGasDelegate.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {EIP712} from "solady/utils/EIP712.sol";
import {IBatchExecution} from "./IBatchExecution.sol";

contract TKGasStation is EIP712, TKGasDelegate {
    // Custom errors
    error BatchSizeExceeded();
    error DeadlineExceeded();
    error InvalidOutputContract();
    error InvalidNonce();
    error InvalidCounter();
    error NotSelf(); 

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

    //TKGasDelegate public immutable TKGlobalGasDelegate; // exact delegate instance for this station
    uint128 public timeboxedCounter;
    uint128 public nonce;
    //mapping(address => uint256) public nonce; //sequentional nonce for each address
    //mapping(address => mapping(address => uint128)) public timeboxedCounter; //timeboxed counter for each address + sender combination to enable blocking a sender

    constructor() EIP712() {
        //TKGlobalGasDelegate = new TKGasDelegate{salt: keccak256(abi.encodePacked(address(this)))}(address(this));
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
        return _hashTypedData(
            keccak256(abi.encode(EXECUTION_TYPEHASH, _nonce, _outputContract, _ethAmount, keccak256(_arguments)))
        );
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
        
        address signer = ECDSA.recover(hash, _signature);
        
        if (signer != address(this)) {
            revert NotSelf();
        }

        if (_nonce == nonce) {
            unchecked {
                nonce = nonce + 1;
            }
            return _execute(_outputContract, _arguments);
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
        
        address signer = ECDSA.recover(hash, _signature);
        
        uint128 currentNonce = nonce;
        
        if (_nonce == currentNonce) {
            unchecked {
                nonce = currentNonce + 1;
            }
            return _execute(_outputContract, _ethAmount, _arguments);
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
        
        address signer = ECDSA.recover(hash, _signature);
        if (_nonce != nonce) {
            revert InvalidNonce();
        }
        if (signer != address(this)) {
            revert NotSelf();
        }
        unchecked {
            ++nonce;
        }
    }

    function burnNonce() external {
        if (msg.sender != address(this)) {
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
        
        address signer = ECDSA.recover(hash, _signature);

        if (_counter != timeboxedCounter) {
            revert InvalidCounter();
        }
        if (signer != address(this)) {
            revert NotSelf();
        }

        return _execute(_outputContract, _ethAmount, _arguments);
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
        
        address signer = ECDSA.recover(hash, _signature);

        if (_counter != timeboxedCounter) {
            revert InvalidCounter();
        }
        if (signer != address(this)) {
            revert NotSelf();
        }
        // Execute the timeboxed transaction (counter does NOT increment for timeboxed)
        return _execute(_outputContract, _arguments);
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
        address signer = ECDSA.recover(hash, _signature);

        if (_counter != timeboxedCounter) {
            revert InvalidCounter();
        }
        if (signer != address(this)) {
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
        return _executeBatch(_executions);
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
        address signer = ECDSA.recover(hash, _signature);

        if (_counter != timeboxedCounter) {
            revert InvalidCounter();
        }
        if (signer != address(this)) {
            revert NotSelf();
        }
        // Execute the timeboxed transaction
        return _execute(_outputContract, _ethAmount, _arguments);
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
        address signer = ECDSA.recover(hash, _signature);

        if (_counter != timeboxedCounter) {
            revert InvalidCounter();
        }
        if (signer != address(this)) {
            revert NotSelf();
        }
        // Execute the timeboxed transaction
        return _executeBatch(_executions);
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
        
        address signer = ECDSA.recover(hash, _signature);

        if (_counter != timeboxedCounter) {
            revert InvalidCounter();
        }
        unchecked {
            ++timeboxedCounter;
        }
    }

    function burnTimeboxedCounter(address _sender) external {
        unchecked {
            ++timeboxedCounter;
        }
    }

    function hashBatchExecution(uint128 _nonce, IBatchExecution.Execution[] memory _executions)
        external
        view
        returns (bytes32)
    {
        return _hashTypedData(
            keccak256(abi.encode(BATCH_EXECUTION_TYPEHASH, _nonce, keccak256(abi.encode(_executions))))
        );
    }

    function executeBatch(uint128 _nonce, IBatchExecution.Execution[] calldata _executions, bytes calldata _signature)
        external
        returns (bool, bytes[] memory)
    {
        // Prevent griefing attacks by limiting batch size
        if (_executions.length > MAX_BATCH_SIZE) {
            revert BatchSizeExceeded();
        }

        bytes32 hash = _hashTypedData(
            keccak256(abi.encode(BATCH_EXECUTION_TYPEHASH, _nonce, keccak256(abi.encode(_executions))))
        );
        address signer = ECDSA.recover(hash, _signature);

        if (_nonce != nonce) {
            revert InvalidNonce();
        }
        if (signer != address(this)) {
            revert NotSelf();
        }
        unchecked {
            ++nonce;
        }

        return _executeBatch(_executions);
    }
}
