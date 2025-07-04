// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {EIP712} from "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import {Ownable} from "openzeppelin-contracts/contracts/access/Ownable.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

import {ITKSmartWalletManager} from "./ITKSmartWalletManager.sol";


contract TKSmartWalletManager is Ownable, EIP712, ITKSmartWalletManager {

    error ExecutionNotAllowed();
    error FunctionNotAllowed();
    error ExecutionFailed();
    error ExecutorBanned();
    error InvalidSignature(bytes signature, bytes32 hash, address signer, address templateContract, address fundingEOA, address executor, uint256 timeout);
    error ValidationFailed();
    error Timeout();
    error AllowedFunctionsTooLong();

    address public immutable interactionContract; 
    bool public immutable functionsLimited; 
    bool public allowExecution; 

    bytes32 public constant TK_SMART_WALLET_EXECUTE_TYPEHASH =
        keccak256("TKSmartWalletExecute(address executor, uint256 timeout)"); // note: chainId and this address are part of the domain separator

    bytes32 public immutable allowedFunctions; // todo just use a mapping instead of this, this can't be saving that much gas 

    mapping(address => bool) public bannedExecutors; 

    constructor(
        string memory _name,
        string memory _version,
        address _owner,
        address _interactionContract,
        bytes4[] memory _allowedFunctions
    ) EIP712(_name, _version) Ownable(_owner) {
        interactionContract = _interactionContract;
        functionsLimited = _allowedFunctions.length > 0;
        if (_allowedFunctions.length > 8) {
            revert AllowedFunctionsTooLong();
        }

        bytes32 tmpAllowedFunctions = 0;
        for (uint256 i = 0; i < _allowedFunctions.length; i++) {
            tmpAllowedFunctions = bytes32(uint256(tmpAllowedFunctions) | (uint256(uint32(_allowedFunctions[i])) << (i * 32)));
        }
        allowedFunctions = tmpAllowedFunctions;
        allowExecution = true;
    }

    function freezeExecution() external onlyOwner {
        allowExecution = false;
    }

    function unfreezeExecution() external onlyOwner {
        allowExecution = true;
    }

    function banExecutor(address _executor) external onlyOwner { 
        bannedExecutors[_executor] = true;
    }

    function unbanExecutor(address _executor) external onlyOwner {
        bannedExecutors[_executor] = false;
    }

    function validateAllReturnInteractionContract(bytes4 _functionId, address _fundingEOA, address _executor, uint256 _timeout, bytes calldata _signature) external view returns (bool, address) {
        if (block.timestamp > _timeout) {
            revert Timeout();
        }
        if (bannedExecutors[_executor]) {
            revert ExecutorBanned();
        }
        if (!isAllowedFunction(_functionId)) {
            revert FunctionNotAllowed();
        }
        if (!validateExecutionSignature(_fundingEOA, _executor, _timeout, _signature)) {
            revert ValidationFailed();
        }
        return (true, interactionContract);
    }

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

    function isAllowedFunction(bytes4 _functionId) public view returns (bool) {
        if (!functionsLimited) {
            return true;
        }
        for (uint256 i = 0; i < 8; i++) {
            if (allowedFunctions & (bytes32(uint256(uint32(_functionId))) << (i * 32)) != 0) {
                return true;
            }
            if ((allowedFunctions >> (i * 32)) & bytes32(0x00000000000000000000000000000000000000000000000000000000FFFFFFFF) == 0) {
                return false;
            }
        }
        return false;
    }
}
