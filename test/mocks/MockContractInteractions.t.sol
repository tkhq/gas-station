pragma solidity ^0.8.30;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract MockContractInteractions {
    function mockSwap(address tokenIn, address tokenOut, uint256 amountIn, uint256 amountOutMin)
        external
        payable
        returns (uint256 amountOut)
    {
        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
        // Mock swap: just transfer the amountOutMin (simulating exact output)
        amountOut = amountOutMin;
        IERC20(tokenOut).transfer(msg.sender, amountOut);
        return amountOut;
    }

    function mockDeposit(address token, uint256 amount) external {
        IERC20(token).transferFrom(msg.sender, address(this), amount);
    }

    function mockDepositEth() external payable returns (uint256) {
        return msg.value;
    }

    function mockWithdraw(address token, uint256 amount) external {
        IERC20(token).transfer(msg.sender, amount);
    }
}
