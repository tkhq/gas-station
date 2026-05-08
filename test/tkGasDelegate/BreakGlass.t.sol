// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {MockDelegate} from "../mocks/MockDelegate.t.sol";
import {TKGasDelegateTestBase as TKGasDelegateBase} from "./TKGasDelegateTestBase.t.sol";
import {TKGasDelegate} from "../../src/TKGasStation/TKGasDelegate.sol";

/// @title BreakGlassTest
/// @notice Verifies the emergency kill switch globally disables every signature-gated path on
/// every delegated EOA after a single transaction by the Turnkey-controlled BREAK_GLASS address.
contract BreakGlassTest is TKGasDelegateBase {
    bytes4 internal constant ERC1271_MAGIC_VALUE = 0x1626ba7e;

    function _activate() internal {
        vm.prank(breakGlass);
        tkGasDelegate.activateBreakGlass();
    }

    function testActivateOnlyByBreakGlass() public {
        assertFalse(tkGasDelegate.killed());

        vm.prank(makeAddr("attacker"));
        vm.expectRevert(TKGasDelegate.NotBreakGlass.selector);
        tkGasDelegate.activateBreakGlass();

        assertFalse(tkGasDelegate.killed());

        _activate();
        assertTrue(tkGasDelegate.killed());
    }

    function testActivateRevertsInDelegatedContext() public {
        // Calling activateBreakGlass through a 7702-delegated EOA must revert because storage
        // would land in the EOA, not the singleton, defeating the global kill.
        vm.prank(breakGlass);
        vm.expectRevert(TKGasDelegate.BreakGlassWrongContext.selector);
        MockDelegate(user).activateBreakGlass();
    }

    function testExecuteRevertsAfterBreakGlass() public {
        _activate();

        address receiver = makeAddr("receiver");
        vm.deal(user, 1 ether);

        uint128 nonce = MockDelegate(user).nonce();
        bytes memory sig = _signExecute(
            USER_PRIVATE_KEY, user, nonce, uint32(block.timestamp + 86400), receiver, 0.1 ether, ""
        );
        bytes memory data =
            _constructExecuteBytes(sig, nonce, uint32(block.timestamp + 86400), receiver, 0.1 ether, "");

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.NotSelf.selector);
        MockDelegate(user).execute(data);

        assertEq(receiver.balance, 0);
        assertEq(MockDelegate(user).nonce(), nonce, "nonce must not advance after kill");
    }

    function testFallbackDispatcherRevertsAfterBreakGlass() public {
        _activate();

        address receiver = makeAddr("receiver_fb");
        vm.deal(user, 1 ether);

        uint128 nonce = MockDelegate(user).nonce();
        bytes memory sig = _signExecute(
            USER_PRIVATE_KEY, user, nonce, uint32(block.timestamp + 86400), receiver, 0.1 ether, ""
        );
        bytes memory fb = _constructFallbackCalldataWithETH(
            nonce, sig, uint32(block.timestamp + 86400), receiver, 0.1 ether, ""
        );

        vm.prank(paymaster);
        (bool ok,) = user.call(fb);
        assertFalse(ok, "fallback dispatcher must revert when killed");
        assertEq(receiver.balance, 0);
    }

    function testSignedBurnNonceRevertsAfterBreakGlass() public {
        _activate();

        uint128 nonce = MockDelegate(user).nonce();
        bytes memory sig = _signBurnNonce(USER_PRIVATE_KEY, user, nonce);

        vm.prank(paymaster);
        vm.expectRevert(TKGasDelegate.NotSelf.selector);
        MockDelegate(user).burnNonce(sig, nonce);
    }

    function testIsValidSignatureFailsAfterBreakGlass() public {
        bytes32 h = keccak256("hello");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_PRIVATE_KEY, h);
        bytes memory sig = abi.encodePacked(r, s, v);

        // Sanity: valid before activation.
        assertEq(MockDelegate(user).isValidSignature(h, sig), ERC1271_MAGIC_VALUE);
        assertTrue(MockDelegate(user).validateSignature(h, sig));

        _activate();

        assertEq(
            MockDelegate(user).isValidSignature(h, sig), bytes4(0xffffffff), "ERC-1271 must reject when killed"
        );
        assertFalse(MockDelegate(user).validateSignature(h, sig));
    }

    function testEoaKeepsControlForRedelegation() public {
        // After break-glass, the EOA's underlying private key is still able to sign a new EIP-7702
        // authorization to a fresh delegate. We model that by re-running vm.signDelegation/attach
        // and confirming code at the EOA now points to the new delegate.
        _activate();

        MockDelegate fresh = new MockDelegate(breakGlass);
        Vm.SignedDelegation memory sd = vm.signDelegation(payable(address(fresh)), USER_PRIVATE_KEY);
        vm.prank(paymaster);
        vm.attachDelegation(sd);

        // Code prefix 0xef0100 + new delegate address.
        bytes memory code = user.code;
        assertEq(code.length, 23);
        address delegatedTo;
        assembly {
            delegatedTo := shr(96, mload(add(code, 0x23)))
        }
        assertEq(delegatedTo, address(fresh));

        // And the fresh delegate is not killed → execute works again.
        address receiver = makeAddr("receiver_after_redelegate");
        vm.deal(user, 1 ether);
        uint128 nonce = MockDelegate(user).nonce();
        bytes memory sig = _signExecute(
            USER_PRIVATE_KEY, user, nonce, uint32(block.timestamp + 86400), receiver, 0.1 ether, ""
        );
        bytes memory data =
            _constructExecuteBytes(sig, nonce, uint32(block.timestamp + 86400), receiver, 0.1 ether, "");

        vm.prank(paymaster);
        MockDelegate(user).execute(data);
        assertEq(receiver.balance, 0.1 ether);
    }
}
