// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {TKGasDelegate} from "../../../TKGasDelegate.sol";

contract PasskeySmartWalletDelegate is TKGasDelegate {

    address internal constant P256_VERIFY = address(0x100);

    error A(bytes a);

    constructor() TKGasDelegate() {}

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "PasskeySmartWalletDelegate";
        version = "1";
    }

    function _validateSignature(bytes32 _hash, bytes calldata _signature) internal view override returns (bool) {
        // note, while this will give a 65 byte signature, the signature is actually 64 bytes and will just ignore the last byte
        return _validatePasskeySignature(_hash, _signature); 
    }

    function _validatePasskeySignature(bytes32 _hash, bytes calldata _signature)
        internal
        view
        returns (bool)
    {
        bytes32 messageHash = sha256(abi.encodePacked(_hash));
        (bytes32 x, bytes32 y) = _getPublicKey();
        bytes memory input =
            abi.encodePacked(messageHash, _signature[0:32], _signature[32:64], x, y);
        (bool success, bytes memory result) = P256_VERIFY.staticcall(input);
        return success && result.length == 32 && abi.decode(result, (uint256)) == 1;
    }

    function getPublicKey() public view returns (bytes32, bytes32) {
        return _getPublicKey();
    }

    function _getPublicKey() internal view returns (bytes32, bytes32) {
        bytes32 x;
        bytes32 y;
        assembly {
            let codePtr := mload(0x40) 
            // Copy code bytes 45-109 (64 bytes) to memory
            extcodecopy(address(), codePtr, 45, 64)
            
            x := mload(codePtr)
            y := mload(add(codePtr, 0x20))
        }
        return (x, y);
    }
}