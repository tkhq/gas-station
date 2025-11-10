// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {TKGasDelegate} from "../../src/TKGasStation/TKGasDelegate.sol";
import {MockDelegate} from "../mocks/MockDelegate.t.sol";
import {TKGasDelegateTestBase} from "./TKGasDelegateTestBase.t.sol";

contract SignatureValidationTest is TKGasDelegateTestBase {
    bytes4 constant ERC1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 constant ERC1271_INVALID_SIGNATURE = 0xffffffff;

    function testValidateSignature_ValidSignature_ReturnsTrue() public view {
        bytes32 messageHash = keccak256("test message");

        // Sign with the contract's private key (user's key)
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_PRIVATE_KEY, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bool isValid = MockDelegate(user).validateSignature(messageHash, signature);
        assertTrue(isValid);
    }

    function testValidateSignature_InvalidSignature_ReturnsFalse() public view {
        bytes32 messageHash = keccak256("test message");

        // Sign with a different private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_PRIVATE_KEY_2, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bool isValid = MockDelegate(user).validateSignature(messageHash, signature);
        assertFalse(isValid);
    }

    function testValidateSignature_WrongHash_ReturnsFalse() public view {
        bytes32 messageHash = keccak256("test message");
        bytes32 wrongHash = keccak256("wrong message");

        // Sign the correct message
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_PRIVATE_KEY, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Validate against wrong hash
        bool isValid = MockDelegate(user).validateSignature(wrongHash, signature);
        assertFalse(isValid);
    }

    function testIsValidSignature_ValidSignature_ReturnsMagicValue() public view {
        bytes32 messageHash = keccak256("test message");

        // Sign with the contract's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_PRIVATE_KEY, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes4 result = MockDelegate(user).isValidSignature(messageHash, signature);
        assertEq(result, ERC1271_MAGIC_VALUE);
    }

    function testIsValidSignature_InvalidSignature_ReturnsInvalidValue() public view {
        bytes32 messageHash = keccak256("test message");

        // Sign with a different private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_PRIVATE_KEY_2, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes4 result = MockDelegate(user).isValidSignature(messageHash, signature);
        assertEq(result, ERC1271_INVALID_SIGNATURE);
    }

    function testIsValidSignature_WrongHash_ReturnsInvalidValue() public view {
        bytes32 messageHash = keccak256("test message");
        bytes32 wrongHash = keccak256("wrong message");

        // Sign the correct message
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_PRIVATE_KEY, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Validate against wrong hash
        bytes4 result = MockDelegate(user).isValidSignature(wrongHash, signature);
        assertEq(result, ERC1271_INVALID_SIGNATURE);
    }

    function testIsValidSignature_EmptySignature_Reverts() public {
        bytes32 messageHash = keccak256("test message");
        bytes memory emptySignature = "";

        vm.expectRevert();
        MockDelegate(user).isValidSignature(messageHash, emptySignature);
    }

    function testIsValidSignature_MalformedSignature_Reverts() public {
        bytes32 messageHash = keccak256("test message");
        bytes memory malformedSignature = "0x1234"; // Too short

        vm.expectRevert();
        MockDelegate(user).isValidSignature(messageHash, malformedSignature);
    }

    function testValidateSignature_WithEIP712Hash_ReturnsTrue() public view {
        // Test with a hash that would be generated from EIP-712
        bytes32 typeHash = keccak256("Execution(uint128 nonce,uint32 deadline,address to,uint256 value,bytes data)");
        bytes32 structHash = keccak256(
            abi.encode(
                typeHash,
                uint128(1),
                uint32(block.timestamp + 1 days),
                address(mockToken),
                uint256(0),
                keccak256("test data")
            )
        );

        // Get the domain separator and hash
        bytes32 domainSeparator = MockDelegate(user).getDomainSeparator();
        bytes32 hash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator, structHash));

        // Sign with the contract's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_PRIVATE_KEY, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bool isValid = MockDelegate(user).validateSignature(hash, signature);
        assertTrue(isValid);
    }

    function testIsValidSignature_WithEIP712Hash_ReturnsMagicValue() public view {
        // Test with a hash that would be generated from EIP-712
        bytes32 typeHash = keccak256("Execution(uint128 nonce,uint32 deadline,address to,uint256 value,bytes data)");
        bytes32 structHash = keccak256(
            abi.encode(
                typeHash,
                uint128(1),
                uint32(block.timestamp + 1 days),
                address(mockToken),
                uint256(0),
                keccak256("test data")
            )
        );

        // Get the domain separator and hash
        bytes32 domainSeparator = MockDelegate(user).getDomainSeparator();
        bytes32 hash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator, structHash));

        // Sign with the contract's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_PRIVATE_KEY, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes4 result = MockDelegate(user).isValidSignature(hash, signature);
        assertEq(result, ERC1271_MAGIC_VALUE);
    }

    function testValidateSignature_DifferentContracts_DifferentResults() public view {
        bytes32 messageHash = keccak256("test message");

        // Sign with user's key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_PRIVATE_KEY, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Should be valid for user's contract
        bool isValidUser = MockDelegate(user).validateSignature(messageHash, signature);
        assertTrue(isValidUser);

        // Should be invalid for user2's contract
        bool isValidUser2 = MockDelegate(user2).validateSignature(messageHash, signature);
        assertFalse(isValidUser2);
    }

    function testIsValidSignature_DifferentContracts_DifferentResults() public view {
        bytes32 messageHash = keccak256("test message");

        // Sign with user's key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_PRIVATE_KEY, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Should return magic value for user's contract
        bytes4 resultUser = MockDelegate(user).isValidSignature(messageHash, signature);
        assertEq(resultUser, ERC1271_MAGIC_VALUE);

        // Should return invalid for user2's contract
        bytes4 resultUser2 = MockDelegate(user2).isValidSignature(messageHash, signature);
        assertEq(resultUser2, ERC1271_INVALID_SIGNATURE);
    }

    function testValidateSignature_ZeroHash_Reverts() public {
        bytes32 zeroHash = bytes32(0);
        bytes memory signature = abi.encodePacked(bytes32(0), bytes32(0), uint8(0));

        vm.expectRevert();
        MockDelegate(user).validateSignature(zeroHash, signature);
    }

    function testIsValidSignature_ZeroHash_Reverts() public {
        bytes32 zeroHash = bytes32(0);
        bytes memory signature = abi.encodePacked(bytes32(0), bytes32(0), uint8(0));

        vm.expectRevert();
        MockDelegate(user).isValidSignature(zeroHash, signature);
    }

    function testValidateSignature_ConsistencyWithIsValidSignature() public view {
        bytes32 messageHash = keccak256("test message");

        // Sign with the contract's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_PRIVATE_KEY, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bool isValid = MockDelegate(user).validateSignature(messageHash, signature);
        bytes4 magicValue = MockDelegate(user).isValidSignature(messageHash, signature);

        // If validateSignature returns true, isValidSignature should return magic value
        if (isValid) {
            assertEq(magicValue, ERC1271_MAGIC_VALUE);
        } else {
            assertEq(magicValue, ERC1271_INVALID_SIGNATURE);
        }
    }

    function testValidateSignature_InvalidSignature_ConsistencyWithIsValidSignature() public view {
        bytes32 messageHash = keccak256("test message");

        // Sign with wrong key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_PRIVATE_KEY_2, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bool isValid = MockDelegate(user).validateSignature(messageHash, signature);
        bytes4 magicValue = MockDelegate(user).isValidSignature(messageHash, signature);

        // Both should indicate invalid
        assertFalse(isValid);
        assertEq(magicValue, ERC1271_INVALID_SIGNATURE);
    }
}
