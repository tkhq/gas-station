// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Gassy} from "./Gassy.sol";
import {LimitedGassy} from "./LimitedGassy.sol";

contract GassyStation {
    constructor() {}

    function createGassy(address _paymaster) external returns (address) {
        return address(new Gassy(_paymaster));
    }

    function createLimitedGassy(address _paymaster, address _presetOutContract) external returns (address) {
        return address(new LimitedGassy(_paymaster, _presetOutContract));
    }
}