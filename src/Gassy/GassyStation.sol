// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Gassy} from "./Gassy.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract GassyStation is EIP712 {
    // EIP712 struct definition
    struct Execution {
        address outputContract;
        uint256 ethAmount;
        bytes arguments;
        uint256 nonce;
    }
    
    // EIP712 type hash
    bytes32 private constant EXECUTION_TYPEHASH = keccak256(
        "Execution(address outputContract,uint256 ethAmount,bytes arguments,uint256 nonce)"
    );

    Gassy public gassy; // just to have the exact gassy instance for this station 

    constructor() EIP712("GassyStation", "1") {
        gassy = new Gassy(address(this));
    }

    function hashExecution(Execution memory _execution) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(EXECUTION_TYPEHASH, _execution)));
    }
    function execute(
        address _outputContract,
        uint256 _ethAmount,
        bytes memory _arguments,
        uint256 _nonce,
        bytes memory _signature
    ) external returns (bool, bytes memory) {
        Execution memory execution = Execution({
            outputContract: _outputContract,
            ethAmount: _ethAmount,
            arguments: _arguments,
            nonce: _nonce
        });
        
        bytes32 hash = hashExecution(execution);
        address signer = ECDSA.recover(hash, _signature);
        return Gassy(payable(signer)).execute(_nonce, _outputContract, _ethAmount, _arguments);
    }

    
}