// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IERC20} from "openzeppelin-contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/token/ERC20/utils/SafeERC20.sol";
import {ITKGasStation} from "../TKGasStation/interfaces/ITKGasStation.sol";

contract PayWithERC20 {
    using SafeERC20 for IERC20;

    address public immutable paymentReceiver;
    address public immutable tkGasStation;

    constructor(address _paymentReceiver, address _tkGasStation) {
        paymentReceiver = _paymentReceiver;
        tkGasStation = _tkGasStation;
    }

    function executePrepay(
        address _token,
        uint256 _amount,
        address _target,
        address _to,
        uint256 _ethAmount,
        bytes calldata _data
    ) external {
        IERC20(_token).safeTransferFrom(_target, paymentReceiver, _amount);
        ITKGasStation(tkGasStation).execute(_target, _to, _ethAmount, _data);
    }

    // Note: This assumes that you get an exchange rate from some offchain oracle
    function executePostPay(
        address _token,
        uint256 _exchangeRate,
        address _target,
        address _to,
        uint256 _ethAmount,
        bytes calldata _data
    ) external {
        uint256 gasBefore = gasleft();
        ITKGasStation(tkGasStation).execute(_target, _to, _ethAmount, _data);
        uint256 gasRemaining = gasleft() - gasBefore;
        IERC20(_token).safeTransferFrom(paymentReceiver, _target, gasRemaining * _exchangeRate);
    }
}
