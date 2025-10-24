// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ITKGasStation} from "../../interfaces/ITKGasStation.sol";

contract PayWithERC20GasStation is ITKGasStation {
    function tkGasDelegate() external view returns (address) {
        return address(this);
    }
}
