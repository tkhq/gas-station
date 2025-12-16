// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {InitializableSmartWalletDelegate} from "../InitializableSmartWalletDelegate.sol";
import {PublicKey} from "../../structs/PublicKey.sol";


contract PasskeySmartWalletDelegate is InitializableSmartWalletDelegate {

    PublicKey public publicKey;
    address internal constant P256_VERIFY = address(0x100);

    constructor(address _initializer) InitializableSmartWalletDelegate(_initializer) {}

    function _initialize(bytes memory _data) internal virtual override returns (bytes memory) {
        publicKey = abi.decode(_data, (PublicKey));
        return _data;
    }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "PasskeySmartWalletDelegate";
        version = "1";
    }

    function _validateSignature(bytes32 _hash, bytes calldata _signature) internal view override returns (bool) {
        // note, while this will give a 65 byte signature, the signature is actually 64 bytes and will just ignore the last byte
        return _validatePasskeySignature(publicKey, _hash, _signature); 
    }

    function _validatePasskeySignature(PublicKey memory _publicKey, bytes32 _hash, bytes calldata _signature)
        internal
        view
        returns (bool)
    {
        bytes32 messageHash = sha256(abi.encodePacked(_hash));
        bytes memory input =
            abi.encodePacked(messageHash, _signature[0:32], _signature[32:64], _publicKey.x, _publicKey.y);
        (bool success, bytes memory result) = P256_VERIFY.staticcall(input);
        return success && result.length == 32 && abi.decode(result, (uint256)) == 1;
    }
}