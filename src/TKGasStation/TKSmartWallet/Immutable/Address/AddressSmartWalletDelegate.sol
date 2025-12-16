// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {TKGasDelegate} from "../../../TKGasDelegate.sol";

import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";

import {LibClone} from "solady/utils/LibClone.sol";

contract AddressSmartWalletDelegate is TKGasDelegate {
    using LibClone for address;

    constructor() TKGasDelegate() {}

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "AddressSmartWalletDelegate";
        version = "1";
    }

    function _validateSignature(bytes32 _hash, bytes calldata _signature) internal view override returns (bool) {
        // this expects the address to be stored at offset 0 in the immutable args
        return SignatureCheckerLib.isValidSignatureNow(_getAuthority(), _hash, _signature);
    }

    function getAuthority() public view returns (address) {
        return _getAuthority();
    }

    function _getAuthority() internal view returns (address) {
        address authority;
        assembly {
            let codePtr := mload(0x40)
            extcodecopy(address(), codePtr, 45, 32) // 45 prefix and 12 null bytes

            authority := mload(codePtr)
        }
        return authority;
    }
}
