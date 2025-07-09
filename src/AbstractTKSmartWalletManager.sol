// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ITKSmartWalletManager} from "./ITKSmartWalletManager.sol";
import {EIP712} from "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";

import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

abstract contract AbstractTKSmartWalletManager is ITKSmartWalletManager, EIP712 {

    error InvalidSignature(bytes signature, bytes32 hash, address signer, address templateContract, address fundingEOA, address executor, uint256 nonce, uint256 timeout);

    bytes32 public constant TK_SMART_WALLET_EXECUTE_TYPEHASH =
        keccak256("TKSmartWalletExecute(address fundingEOA, address executor, uint256 nonce, uint256 timeout, uint256 ethAmount, bytes executionData)"); // note: chainId and this address are part of the domain separator

    address public immutable interactionContract; 

    constructor(string memory _name, string memory _version, address _interactionContract) EIP712(_name, _version) {
        interactionContract = _interactionContract;
    }

    function _validateExecutionSignature(address _fundingEOA, address _executor, uint256 _nonce, uint256 _timeout, uint256 _ethAmount, bytes memory _executionData, bytes calldata _signature) internal view returns (bool) {

        bytes32 hash = getHash(_fundingEOA, _executor, _nonce, _timeout, _ethAmount, _executionData);
        address signer = ECDSA.recover(hash, _signature);

        if (signer != _executor) {
            revert InvalidSignature(_signature, hash, signer, address(this), _fundingEOA, _executor, _nonce, _timeout);
        }

        return signer == _executor;
    }

    function getHash(address _fundingEOA, address _executor, uint256 _nonce, uint256 _timeout, uint256 _ethAmount, bytes memory _executionData) public view returns (bytes32) { // todo remove this and use internal functions properly 
        return _hashTypedDataV4(keccak256(abi.encode(TK_SMART_WALLET_EXECUTE_TYPEHASH, _fundingEOA, _executor, _nonce, _timeout, _ethAmount, _executionData)));
    }

    function validateAllReturnInteractionContract(address _executor, uint256 _nonce, uint256 _timeout, uint256 _ethAmount, bytes memory _executionData, bytes calldata _signature) external virtual returns (bool, address);

    function validateExecutionDataOnlyReturnInteractionContract(uint256 _ethAmount, bytes memory _executionData) external virtual returns (bool, address);

    function validateExecutionSignature(address _executor, uint256 _nonce, uint256 _timeout, uint256 _ethAmount, bytes memory _executionData, bytes calldata _signature) external virtual returns (bool);

    function getNonce(address _eoa7702, address _executor) external virtual view returns (uint256);
}