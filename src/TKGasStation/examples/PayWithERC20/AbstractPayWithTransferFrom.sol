// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AbstractPayWithERC20GasStation} from "./AbstractPayWithERC20GasStation.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

abstract contract AbstractPayWithTransferFrom is AbstractPayWithERC20GasStation {
    using SafeERC20 for IERC20;

    constructor(address _tkGasDelegate, address _paymentToken, address _owner)
        AbstractPayWithERC20GasStation(_tkGasDelegate, _paymentToken, _owner)
    {}

    function _reimburseGasCost(address _token, uint256 _amount, address _from, address _recipient)
        internal
        override
        returns (uint256)
    {
        uint256 toReimburse = _getExchangeRate(_token, _amount);
        IERC20(_token).safeTransferFrom(_from, _recipient, toReimburse);
        return toReimburse;
    }
}
