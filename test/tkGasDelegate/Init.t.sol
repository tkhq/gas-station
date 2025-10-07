// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {TKGasDelegate} from "../../src/TKGasStation/TKGasDelegate.sol";
import {TKGasDelegateTestBase as TKGasDelegateBase} from "./TKGasDelegateTestBase.sol";

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
        (uint128 sessionCounter, uint128 nonce) = TKGasDelegate(user).state();
        assertEq(nonce, 0);
        assertEq(sessionCounter, 0);
    }
}

