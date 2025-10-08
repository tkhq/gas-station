// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {MockDelegate} from "../mocks/MockDelegate.t.sol";
import {TKGasDelegateTestBase as TKGasDelegateBase} from "./TKGasDelegateTestBase.t.sol";

contract InitTest is TKGasDelegateBase {
    function testGassyStationDeployment() public view {
        assertTrue(payable(address(tkGasDelegate)) != address(0));
    }

    function testGassyCreation() public view {
        assertTrue(payable(address(tkGasDelegate)) != address(0));
    }

    function testGassyDelegationInit() public view {
        bytes memory code = address(user).code;
        assertGt(code.length, 0);
        uint128 nonce = MockDelegate(user).nonce();
        assertEq(nonce, 0);
    }
}
