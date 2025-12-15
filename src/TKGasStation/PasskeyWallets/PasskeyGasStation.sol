// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {TKGasStation} from "../TKGasStation.sol";

contract PasskeyGasStation is TKGasStation {
    error A(bytes a, address b);

    constructor(address _tkGasDelegate) TKGasStation(_tkGasDelegate) {}
    function _isDelegated(address _targetEoA) internal override view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(_targetEoA)
        }

        // 1) Check runtime length matches LibClone minimal proxy (44 bytes / 0x2c).
        if (size != 0x2c) {
            return false;
        }
        bytes memory code = new bytes(size);
        assembly {
            extcodecopy(_targetEoA, add(code, 0x20), 0, size)
        }

        // LibClone minimal proxy prefix: 0x363d3d373d3d3d363d73 (10 bytes)
        bytes10 expectedPrefix = 0x363d3d373d3d3d363d73;
        bytes10 codePrefix;
        address delegatedTo;

        assembly {
            // Load prefix from bytes 0-9 (first 10 bytes of runtime code)
            codePrefix := mload(add(code, 0x20))
            // Load implementation address from bytes 10-29
            // mload at offset 0x2a loads bytes 10-41, then shr(96) extracts the rightmost 20 bytes
            delegatedTo := shr(96, mload(add(code, 0x2a))) // 0x20 (array data offset) + 10 (byte offset)
        }
        if (codePrefix != expectedPrefix) {
            revert A(abi.encodePacked(codePrefix), TK_GAS_DELEGATE);
            return false;
        }

        if (delegatedTo != TK_GAS_DELEGATE) {
            revert A(abi.encodePacked(delegatedTo), TK_GAS_DELEGATE);
            return false;
        }

        // 4) Check suffix: 0x5af43d3d93803e602a57fd5bf3 (13 bytes) at the end.
        /*bytes13 expectedSuffix = 0x5af43d3d93803e602a57fd5bf3;
        bytes13 codeSuffix;
        assembly {
            // Start at byte index 31 (0-based) => 0x20 + 31 = 0x3f
            codeSuffix := mload(add(code, 0x3f))
        }
        if (codeSuffix != expectedSuffix) {
            return false;
        }
*/
        return true;
    }

}

