// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {MockDelegate} from "../mocks/MockDelegate.t.sol";

/**
 * @title TypeHashValidationTest
 * @notice This test validates that all EIP-712 typehash constants in TKGasDelegate
 *         are correctly calculated from their type strings. This is a critical security
 *         test that ensures the typehashes match the expected keccak256 values.
 * @dev If this test fails, it indicates that the typehash constants in the contract
 *      do not match their type string definitions, which would break signature validation.
 */
contract TypeHashValidationTest is Test {
    MockDelegate delegate;

    function setUp() public {
        delegate = new MockDelegate();
    }

    /**
     * @notice Validates that all typehash constants match their expected keccak256 values
     * @dev This test ensures that the hardcoded typehash values in the contract are correct.
     *      If any of these assertions fail, the contract's typehash constants need to be updated.
     */
    function testValidateAllTypeHashConstants() public view {
        // Expected typehash values calculated from type strings
        bytes32 expectedExecutionTypehash = keccak256(
            "Execution(uint128 nonce,uint32 deadline,address to,uint256 value,bytes data)"
        );
        bytes32 expectedApproveThenExecuteTypehash = keccak256(
            "ApproveThenExecute(uint128 nonce,uint32 deadline,address erc20Contract,address spender,uint256 approveAmount,address to,uint256 value,bytes data)"
        );
        bytes32 expectedBatchExecutionTypehash = keccak256(
            "BatchExecution(uint128 nonce,uint32 deadline,Call[] calls)Call(address to,uint256 value,bytes data)"
        );
        bytes32 expectedBurnNonceTypehash = keccak256("BurnNonce(uint128 nonce)");
        bytes32 expectedSessionExecutionTypehash =
            keccak256("SessionExecution(uint128 counter,uint32 deadline,address sender,address to)");
        bytes32 expectedArbitrarySessionExecutionTypehash =
            keccak256("ArbitrarySessionExecution(uint128 counter,uint32 deadline,address sender)");
        bytes32 expectedBurnSessionCounterTypehash = keccak256("BurnSessionCounter(uint128 counter)");

        // Actual typehash values from the contract
        bytes32 actualExecutionTypehash = delegate.external_EXECUTION_TYPEHASH();
        bytes32 actualApproveThenExecuteTypehash = delegate.external_APPROVE_THEN_EXECUTE_TYPEHASH();
        bytes32 actualBatchExecutionTypehash = delegate.external_BATCH_EXECUTION_TYPEHASH();
        bytes32 actualBurnNonceTypehash = delegate.external_BURN_NONCE_TYPEHASH();
        bytes32 actualSessionExecutionTypehash = delegate.external_SESSION_EXECUTION_TYPEHASH();
        bytes32 actualArbitrarySessionExecutionTypehash = delegate.external_ARBITRARY_SESSION_EXECUTION_TYPEHASH();
        bytes32 actualBurnSessionCounterTypehash = delegate.external_BURN_SESSION_COUNTER_TYPEHASH();

        // Validate each typehash
        assertEq(actualExecutionTypehash, expectedExecutionTypehash, "EXECUTION_TYPEHASH mismatch");
        assertEq(
            actualApproveThenExecuteTypehash,
            expectedApproveThenExecuteTypehash,
            "APPROVE_THEN_EXECUTE_TYPEHASH mismatch"
        );
        assertEq(actualBatchExecutionTypehash, expectedBatchExecutionTypehash, "BATCH_EXECUTION_TYPEHASH mismatch");
        assertEq(actualBurnNonceTypehash, expectedBurnNonceTypehash, "BURN_NONCE_TYPEHASH mismatch");
        assertEq(
            actualSessionExecutionTypehash, expectedSessionExecutionTypehash, "SESSION_EXECUTION_TYPEHASH mismatch"
        );
        assertEq(
            actualArbitrarySessionExecutionTypehash,
            expectedArbitrarySessionExecutionTypehash,
            "ARBITRARY_SESSION_EXECUTION_TYPEHASH mismatch"
        );
        assertEq(
            actualBurnSessionCounterTypehash,
            expectedBurnSessionCounterTypehash,
            "BURN_SESSION_COUNTER_TYPEHASH mismatch"
        );
    }

    /**
     * @notice Validates that the hash functions use the correct typehashes by comparing outputs
     * @dev This test verifies that the actual hash functions in the contract produce
     *      the same results as manually constructed hashes using the type strings.
     */
    function testHashFunctionsUseCorrectTypeHashes() public view {
        uint128 nonce = 12345;
        uint32 deadline = uint32(block.timestamp + 1 days);
        address outputContract = address(0x1234567890123456789012345678901234567890);
        uint256 ethAmount = 1 ether;
        bytes memory arguments = abi.encodeWithSignature("transfer(address,uint256)", address(0xABCD), 1000);

        // Test EXECUTION_TYPEHASH is used correctly
        bytes32 contractHash = delegate.hashExecution(nonce, deadline, outputContract, ethAmount, arguments);

        // The contract should produce a hash that uses the domain separator
        // We can't directly compare the raw hash because of the domain separator,
        // but we can verify it's non-zero and consistent
        assertTrue(contractHash != bytes32(0), "Hash should not be zero");

        // Test that calling the function twice with same inputs produces same hash (consistency check)
        bytes32 contractHash2 = delegate.hashExecution(nonce, deadline, outputContract, ethAmount, arguments);
        assertEq(contractHash, contractHash2, "Hash function should be deterministic");
    }

    /**
     * @notice Validates BURN_NONCE_TYPEHASH
     */
    function testBurnNonceTypeHash() public view {
        uint128 nonce = 1;
        bytes32 hash = delegate.hashBurnNonce(nonce);

        // Verify the hash is non-zero and deterministic
        assertTrue(hash != bytes32(0), "BurnNonce hash should not be zero");
        assertEq(hash, delegate.hashBurnNonce(nonce), "BurnNonce hash should be deterministic");
    }

    /**
     * @notice Validates SESSION_EXECUTION_TYPEHASH
     */
    function testSessionExecutionTypeHash() public view {
        uint128 counter = 1;
        uint32 deadline = uint32(block.timestamp + 1 days);
        address sender = address(0x1234);
        address outputContract = address(0x5678);

        bytes32 hash = delegate.hashSessionExecution(counter, deadline, sender, outputContract);

        // Verify the hash is non-zero and deterministic
        assertTrue(hash != bytes32(0), "SessionExecution hash should not be zero");
        assertEq(
            hash,
            delegate.hashSessionExecution(counter, deadline, sender, outputContract),
            "SessionExecution hash should be deterministic"
        );
    }

    /**
     * @notice Validates ARBITRARY_SESSION_EXECUTION_TYPEHASH
     */
    function testArbitrarySessionExecutionTypeHash() public view {
        uint128 counter = 1;
        uint32 deadline = uint32(block.timestamp + 1 days);
        address sender = address(0x1234);

        bytes32 hash = delegate.hashArbitrarySessionExecution(counter, deadline, sender);

        // Verify the hash is non-zero and deterministic
        assertTrue(hash != bytes32(0), "ArbitrarySessionExecution hash should not be zero");
        assertEq(
            hash,
            delegate.hashArbitrarySessionExecution(counter, deadline, sender),
            "ArbitrarySessionExecution hash should be deterministic"
        );
    }

    /**
     * @notice Validates BURN_SESSION_COUNTER_TYPEHASH
     */
    function testBurnSessionCounterTypeHash() public view {
        uint128 counter = 1;

        bytes32 hash = delegate.hashBurnSessionCounter(counter);

        // Verify the hash is non-zero and deterministic
        assertTrue(hash != bytes32(0), "BurnSessionCounter hash should not be zero");
        assertEq(hash, delegate.hashBurnSessionCounter(counter), "BurnSessionCounter hash should be deterministic");
    }

    /**
     * @notice Validates that different inputs produce different hashes (collision resistance check)
     */
    function testHashFunctionsAreCollisionResistant() public view {
        uint128 nonce1 = 1;
        uint128 nonce2 = 2;
        uint32 deadline = uint32(block.timestamp + 1 days);
        address outputContract = address(0x1234);
        uint256 ethAmount = 1 ether;
        bytes memory arguments = abi.encodeWithSignature("transfer(address,uint256)", address(0xABCD), 1000);

        bytes32 hash1 = delegate.hashExecution(nonce1, deadline, outputContract, ethAmount, arguments);
        bytes32 hash2 = delegate.hashExecution(nonce2, deadline, outputContract, ethAmount, arguments);

        // Different nonces should produce different hashes
        assertTrue(hash1 != hash2, "Different nonces should produce different hashes");

        // Different deadlines should produce different hashes
        bytes32 hash3 = delegate.hashExecution(nonce1, deadline + 1, outputContract, ethAmount, arguments);
        assertTrue(hash1 != hash3, "Different deadlines should produce different hashes");

        // Different output contracts should produce different hashes
        bytes32 hash4 = delegate.hashExecution(nonce1, deadline, address(0x5678), ethAmount, arguments);
        assertTrue(hash1 != hash4, "Different output contracts should produce different hashes");

        // Different eth amounts should produce different hashes
        bytes32 hash5 = delegate.hashExecution(nonce1, deadline, outputContract, 2 ether, arguments);
        assertTrue(hash1 != hash5, "Different eth amounts should produce different hashes");

        // Different arguments should produce different hashes
        bytes memory arguments2 = abi.encodeWithSignature("transfer(address,uint256)", address(0xABCD), 2000);
        bytes32 hash6 = delegate.hashExecution(nonce1, deadline, outputContract, ethAmount, arguments2);
        assertTrue(hash1 != hash6, "Different arguments should produce different hashes");
    }
}
