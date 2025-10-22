// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IERC20} from "openzeppelin-contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/token/ERC20/utils/SafeERC20.sol";
import {ITKGasStation} from "../TKGasStation/interfaces/ITKGasStation.sol";

contract PayWithERC20 {
    using SafeERC20 for IERC20;

    address public immutable paymentReceiver; // todo make ownable instead
    address public immutable tkGasStation;
    address public immutable payToken;

    uint256 public constant MAX_GAS = 1000000;

    uint256 public amountToWithdraw;

    mapping(address => uint256) public prePayAmounts;

    constructor(address _paymentReceiver, address _tkGasStation, address _payToken) {
        paymentReceiver = _paymentReceiver;
        tkGasStation = _tkGasStation;
        payToken = _payToken;
    }

    function setPrePayAmount(address _target, uint256 _amount) external {
        IERC20(payToken).safeTransferFrom(_target, paymentReceiver, _amount);
        prePayAmounts[_target] = _amount; // bad
    }

    // Note: This assumes that you get an exchange rate from some offchain oracle
    function executePay(address _target, address _to, uint256 _ethAmount, bytes calldata _data) external {
        uint256 gasBefore = gasleft();
        ITKGasStation(tkGasStation).execute(_target, _to, _ethAmount, _data);
        uint256 gasCost = gasleft() - gasBefore;
        uint256 chuckECheeseToken = gasCost * MAX_GAS;
        prePayAmounts[_target] -= chuckECheeseToken; // will error if not enough
    }
}
