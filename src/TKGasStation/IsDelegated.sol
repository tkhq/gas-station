// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @title IsDelegated
/// @notice Library for checking if an address is delegated to a specific implementation
library IsDelegated {
    /// @notice Checks if an address is delegated using the standard 23-byte delegation pattern (0xef0100 prefix)
    /// @param _targetEoA The address to check for delegation
    /// @param _expectedDelegate The expected delegate implementation address
    /// @return true if the address is delegated to the expected delegate, false otherwise
    function isDelegatedStandard(address _targetEoA, address _expectedDelegate) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(_targetEoA)
        }
        if (size != 23) {
            return false;
        }

        bytes memory code = new bytes(23);
        assembly {
            extcodecopy(_targetEoA, add(code, 0x20), 0, 23)
        }
        // prefix is 0xef0100
        if (code[0] != 0xef || code[1] != 0x01 || code[2] != 0x00) {
            return false;
        }

        address delegatedTo;

        assembly {
            // Load the 20-byte address from bytes 3-22
            delegatedTo := shr(96, mload(add(code, 0x23)))
        }

        return delegatedTo == _expectedDelegate;
    }

    /// @notice Checks if an address is delegated using the LibClone minimal proxy pattern (44-byte runtime code)
    /// @param _targetEoA The address to check for delegation
    /// @param _expectedDelegate The expected delegate implementation address
    /// @param _expectedRuntimeCodeSize The expected runtime code size (recommended: 0x2c for Solady's LibClone, 44 bytes)
    /// @param _expectedPrefix The expected code prefix (recommended: 0x3d3d3d3d363d3d37363d73 for Solady's LibClone, 11 bytes)
    /// @param _expectedSuffix The expected code suffix (recommended: 0x5af43d3d93803e602a57fd5bf3 for Solady's LibClone, 13 bytes)
    /// @return true if the address is delegated to the expected delegate, false otherwise
    function isDelegatedMinimalProxy(
        address _targetEoA,
        address _expectedDelegate,
        uint256 _expectedRuntimeCodeSize,
        bytes11 _expectedPrefix,
        bytes13 _expectedSuffix
    ) internal view returns (bool) {
        // Recommended values for Solady's LibClone minimal proxy:
        // _expectedRuntimeCodeSize = 0x2c (44 bytes)
        // _expectedPrefix = 0x3d3d3d3d363d3d37363d73 (11 bytes)
        // _expectedSuffix = 0x5af43d3d93803e602a57fd5bf3 (13 bytes)
        bytes11 codePrefix;
        address delegatedTo;
        bytes13 codeSuffix;

        assembly {
            // Get code size
            let size := extcodesize(_targetEoA)
            
            // Check runtime length matches LibClone minimal proxy (44 bytes / 0x2c)
            // If size doesn't match, set values to zero which will fail the final check
            if eq(size, _expectedRuntimeCodeSize) {
                // Allocate memory for code (free memory pointer)
                let codePtr := mload(0x40)
                
                // Copy runtime code to memory
                extcodecopy(_targetEoA, codePtr, 0, size)
                
                // Extract prefix (first 11 bytes)
                codePrefix := mload(codePtr)
                
                // Extract delegated address (bytes 11-30, 20 bytes)
                delegatedTo := shr(96, mload(add(codePtr, 11)))
                
                // Extract suffix (last 13 bytes, starting at byte 31)
                codeSuffix := mload(add(codePtr, 31))
            }
        }
        
        return codePrefix == _expectedPrefix && delegatedTo == _expectedDelegate && codeSuffix == _expectedSuffix;
    }
}

