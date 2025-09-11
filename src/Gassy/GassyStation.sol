// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Gassy} from "./Gassy.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract GassyStation is EIP712 {
    // EIP712 type hash
    bytes32 private constant EXECUTION_TYPEHASH =
        keccak256("Execution(uint256 nonce,address outputContract,uint256 ethAmount,bytes arguments)");

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
}
