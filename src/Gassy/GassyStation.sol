// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Gassy} from "./Gassy.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {IBatchExecution} from "./IBatchExecution.sol";

contract GassyStation is EIP712 {
    // Custom errors
    error BatchSizeExceeded();
    error DeadlineExceeded();

    // EIP712 type hashes (precomputed for gas optimization)
    bytes32 private constant EXECUTION_TYPEHASH = 
        0xcd5f5d65a387f188fe5c0c9265c7e7ec501fa0b0ee45ad769c119694cac5d895;
    // Original: keccak256("Execution(uint128 nonce,address outputContract,uint256 ethAmount,bytes arguments)")
    
    bytes32 private constant BATCH_EXECUTION_TYPEHASH = 
        0xed21856ca46c7c7ce0790b072d33d166bd875a642ee8d1e4d0ba23b181c1e7df;
    // Original: keccak256("BatchExecution(uint128 nonce,Execution[] executions)Execution(uint128 nonce,address outputContract,uint256 ethAmount,bytes arguments)")
    
    bytes32 private constant BURN_NONCE_TYPEHASH = 
        0x1abb8920e48045adda3ed0ce4be4357be95d4aa21af287280f532fc031584bda;
    // Original: keccak256("BurnNonce(uint128 nonce)")
    
    bytes32 private constant TIMEBOXED_EXECUTION_TYPEHASH = 
        0x572542ff5f8730cc3585cab0d01b4696eadf4bd390c1dbbaa4467a76cb6f95bf;
    // Original: keccak256("TimeboxedExecution(uint128 counter,uint128 deadline,address sender,address outputContract)")
    
    bytes32 private constant ARBITRARY_TIMEBOXED_EXECUTION_TYPEHASH = 
        0xc0d6acc328e7656b4ab6234f5efb8bc56b83d5b67d829ae64ea7ebe07f0968ee;
    // Original: keccak256("ArbitraryTimeboxedExecution(uint128 counter,uint128 deadline,address sender)")
    
    bytes32 private constant BURN_TIMEBOXED_COUNTER_TYPEHASH = 
        0x9d7c8bed876f7441d00239a75cdc94ef7a45d0ffb8c804be7d5aee5dcfa1764d;
    // Original: keccak256("BurnTimeboxedCounter(uint128 counter)")

    // Maximum batch size to prevent griefing attacks
    uint256 public constant MAX_BATCH_SIZE = 50;

    Gassy public immutable gassy; // just to have the exact gassy instance for this station

    constructor() EIP712("GassyStation", "1") {
        gassy = new Gassy(address(this));
    }

    function hashExecution(uint128 _nonce, address _outputContract, uint256 _ethAmount, bytes memory _arguments)
        external
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(
            keccak256(abi.encode(EXECUTION_TYPEHASH, _nonce, _outputContract, _ethAmount, keccak256(_arguments)))
        );
    }

    function execute(uint128 _nonce, address _outputContract, bytes calldata _arguments, bytes calldata _signature)
        external
        returns (bool, bytes memory)
    {
        bytes32 hash = _hashTypedDataV4(
            keccak256(abi.encode(EXECUTION_TYPEHASH, _nonce, _outputContract, 0, keccak256(_arguments)))
        );
        address signer = ECDSA.recover(hash, _signature);

        return Gassy(payable(signer)).execute(_nonce, _outputContract, _arguments);
    }

    function execute(
        uint128 _nonce,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments,
        bytes calldata _signature
    ) external returns (bool, bytes memory) {
        bytes32 hash = _hashTypedDataV4(
            keccak256(abi.encode(EXECUTION_TYPEHASH, _nonce, _outputContract, _ethAmount, keccak256(_arguments)))
        );
        address signer = ECDSA.recover(hash, _signature);

        return Gassy(payable(signer)).execute(_nonce, _outputContract, _ethAmount, _arguments);
    }

    function hashBurnNonce(uint128 _nonce)
        external
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(
            keccak256(abi.encode(BURN_NONCE_TYPEHASH, _nonce))
        );
    }

    function burnNonce(
        uint128 _nonce,
        bytes calldata _signature
    ) external {
        bytes32 hash = _hashTypedDataV4(
            keccak256(abi.encode(BURN_NONCE_TYPEHASH, _nonce))
        );
        address signer = ECDSA.recover(hash, _signature);

        Gassy(payable(signer)).burnNonce(_nonce);
    }

    function hashTimeboxedExecution(
        uint128 _counter,
        uint128 _deadline,
        address _sender,
        address _outputContract
    )
        external
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(
            keccak256(abi.encode(TIMEBOXED_EXECUTION_TYPEHASH, _counter, _deadline, _sender, _outputContract))
        );
    }

    function hashArbitraryTimeboxedExecution(
        uint128 _counter,
        uint128 _deadline,
        address _sender
    )
        external
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(
            keccak256(abi.encode(ARBITRARY_TIMEBOXED_EXECUTION_TYPEHASH, _counter, _deadline, _sender))
        );
    }

    function hashBurnTimeboxedCounter(uint128 _counter)
        external
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(
            keccak256(abi.encode(BURN_TIMEBOXED_COUNTER_TYPEHASH, _counter))
        );
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

        bytes32 hash = _hashTypedDataV4(
            keccak256(abi.encode(TIMEBOXED_EXECUTION_TYPEHASH, _counter, _deadline, msg.sender, _outputContract))
        );
        address signer = ECDSA.recover(hash, _signature);

        // Execute the timeboxed transaction
        return Gassy(payable(signer)).executeTimeboxed(_counter, _outputContract, _ethAmount, _arguments);
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

        bytes32 hash = _hashTypedDataV4(
            keccak256(abi.encode(ARBITRARY_TIMEBOXED_EXECUTION_TYPEHASH, _counter, _deadline, msg.sender))
        );
        address signer = ECDSA.recover(hash, _signature);

        // Execute the timeboxed transaction
        return Gassy(payable(signer)).executeTimeboxed(_counter, _outputContract, _ethAmount, _arguments);
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
        
        bytes32 hash = _hashTypedDataV4(
            keccak256(abi.encode(ARBITRARY_TIMEBOXED_EXECUTION_TYPEHASH, _counter, _deadline, msg.sender))
        );
        address signer = ECDSA.recover(hash, _signature);

        // Execute the timeboxed transaction
        return Gassy(payable(signer)).executeBatchTimeboxed(_counter, _executions);

    }

    function burnTimeboxedCounter(
        uint128 _counter,
        bytes calldata _signature
    ) external {
        bytes32 hash = _hashTypedDataV4(
            keccak256(abi.encode(BURN_TIMEBOXED_COUNTER_TYPEHASH, _counter))
        );
        address signer = ECDSA.recover(hash, _signature);

        Gassy(payable(signer)).burnTimeboxedCounter(_counter);
    }

    function hashBatchExecution(uint128 _nonce, IBatchExecution.Execution[] memory _executions)
        external
        view
        returns (bytes32)
    {
        bytes32[] memory executionHashes = new bytes32[](_executions.length);
        for (uint8 i = 0; i < _executions.length;) {
            executionHashes[i] = keccak256(
                abi.encode(
                    EXECUTION_TYPEHASH,
                    _executions[i].nonce,
                    _executions[i].outputContract,
                    _executions[i].ethAmount,
                    keccak256(_executions[i].arguments)
                )
            );
            unchecked { ++i; }
        }
        
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    BATCH_EXECUTION_TYPEHASH,
                    _nonce,
                    keccak256(abi.encodePacked(executionHashes))
                )
            )
        );
    }

    function executeBatch(
        uint128 _nonce,
        IBatchExecution.Execution[] calldata _executions,
        bytes calldata _signature
    ) external returns (bool, bytes[] memory) {
        // Prevent griefing attacks by limiting batch size
        if (_executions.length > MAX_BATCH_SIZE) {
            revert BatchSizeExceeded();
        }
        
        bytes32[] memory executionHashes = new bytes32[](_executions.length);
        for (uint8 i = 0; i < _executions.length;) {
            executionHashes[i] = keccak256(
                abi.encode(
                    EXECUTION_TYPEHASH,
                    _executions[i].nonce,
                    _executions[i].outputContract,
                    _executions[i].ethAmount,
                    keccak256(_executions[i].arguments)
                )
            );
            unchecked { ++i; }
        }
        
        bytes32 hash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    BATCH_EXECUTION_TYPEHASH,
                    _nonce,
                    keccak256(abi.encodePacked(executionHashes))
                )
            )
        );
        address signer = ECDSA.recover(hash, _signature);
        
        return Gassy(payable(signer)).executeBatch(_nonce, _executions);
    }
}
