// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ITKSmartWalletManager} from "./ITKSmartWalletManager.sol";
import {EIP712} from "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";

import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

abstract contract AbstractTKSmartWalletManager is ITKSmartWalletManager, EIP712 {

    error InvalidSignature(bytes signature, bytes32 hash, address signer, address templateContract, address fundingEOA, address executor, uint256 timeout);

    bytes32 public constant TK_SMART_WALLET_EXECUTE_TYPEHASH =
        keccak256("TKSmartWalletExecute(address executor, uint256 timeout)"); // note: chainId and this address are part of the domain separator

    function validateExecutionSignature(address _fundingEOA, address _executor, uint256 _timeout, bytes calldata _signature) public view returns (bool) {

        bytes32 hash = getHash(_executor, _timeout);
        address signer = ECDSA.recover(hash, _signature);

        if (signer != _fundingEOA) {
            revert InvalidSignature(_signature, hash, signer, address(this), _fundingEOA, _executor, _timeout);
        }

        return signer == _fundingEOA;
    }

    function getHash(address _executor, uint256 _timeout) public view returns (bytes32) { // todo remove this and use internal functions properly 
        return _hashTypedDataV4(keccak256(abi.encode(TK_SMART_WALLET_EXECUTE_TYPEHASH, _executor, _timeout)));
    }

    function validateAllReturnInteractionContract(address _fundingEOA, address _executor, uint256 _timeout, bytes calldata _signature, uint256 _ethAmount, bytes memory _executionData) external virtual view returns (bool, address);

}