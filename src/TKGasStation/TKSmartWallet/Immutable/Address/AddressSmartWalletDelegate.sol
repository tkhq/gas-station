// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {InitializableSmartWalletDelegate} from "../InitializableSmartWalletDelegate.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";

contract AddressSmartWalletDelegate is InitializableSmartWalletDelegate {

    address public authority;

    constructor(address _initializer) InitializableSmartWalletDelegate(_initializer) {}

    function _initialize(bytes memory _data) internal virtual override returns (bytes memory) {
        authority = abi.decode(_data, (address));
        return _data;
    }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "AddressSmartWalletDelegate";
        version = "1";
    }

    function _validateSignature(bytes32 _hash, bytes calldata _signature) internal view override returns (bool) {
        return SignatureCheckerLib.isValidSignatureNow(authority, _hash, _signature);
    }
}