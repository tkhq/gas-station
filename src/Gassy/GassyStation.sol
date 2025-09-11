// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Gassy} from "./Gassy.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {IBatchExecution} from "./IBatchExecution.sol";

contract GassyStation is EIP712 {
    // EIP712 type hashes
    bytes32 private constant EXECUTION_TYPEHASH =
        keccak256("Execution(uint256 nonce,address outputContract,uint256 ethAmount,bytes arguments)");
    
    bytes32 private constant BATCH_EXECUTION_TYPEHASH =
        keccak256("BatchExecution(uint256 nonce,Execution[] executions)Execution(uint256 nonce,address outputContract,uint256 ethAmount,bytes arguments)");
    
    bytes32 private constant BURN_NONCE_TYPEHASH =
        keccak256("BurnNonce(uint256 nonce)");

    // Maximum batch size to prevent griefing attacks
    uint256 public constant MAX_BATCH_SIZE = 50;

    Gassy public immutable gassy; // just to have the exact gassy instance for this station

    constructor() EIP712("GassyStation", "1") {
        gassy = new Gassy(address(this));
    }

    function hashExecution(uint256 _nonce, address _outputContract, uint256 _ethAmount, bytes memory _arguments)
        external
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(
            keccak256(abi.encode(EXECUTION_TYPEHASH, _nonce, _outputContract, _ethAmount, keccak256(_arguments)))
        );
    }

    function execute(uint256 _nonce, address _outputContract, bytes calldata _arguments, bytes calldata _signature)
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
        uint256 _nonce,
        address _outputContract,
        uint256 _ethAmount,
        bytes calldata _arguments,
        bytes calldata _signature
    ) external returns (bool, bytes memory) {
        bytes32 hash = _hashTypedDataV4(
            keccak256(abi.encode(EXECUTION_TYPEHASH, _nonce, _outputContract, _ethAmount, keccak256(_arguments)))
        );
        address signer = ECDSA.recover(hash, _signature);

        // Choose the appropriate function based on ETH amount
        if (_ethAmount == 0) {
            return Gassy(payable(signer)).execute(_nonce, _outputContract, _arguments);
        }
        return Gassy(payable(signer)).execute(_nonce, _outputContract, _ethAmount, _arguments);
    }

    function hashBurnNonce(uint256 _nonce)
        external
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(
            keccak256(abi.encode(BURN_NONCE_TYPEHASH, _nonce))
        );
    }

    function burnNonce(
        uint256 _nonce,
        bytes calldata _signature
    ) external {
        bytes32 hash = _hashTypedDataV4(
            keccak256(abi.encode(BURN_NONCE_TYPEHASH, _nonce))
        );
        address signer = ECDSA.recover(hash, _signature);

        Gassy(payable(signer)).burnNonce(_nonce);
    }


    function hashBatchExecution(uint256 _nonce, IBatchExecution.Execution[] memory _executions)
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
        uint256 _nonce,
        IBatchExecution.Execution[] calldata _executions,
        bytes calldata _signature
    ) external returns (bool[] memory, bytes[] memory) {
        // Prevent griefing attacks by limiting batch size
        if (_executions.length > MAX_BATCH_SIZE) {
            assembly { revert(0, 3) } // BatchSizeExceeded
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
