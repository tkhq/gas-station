pragma solidity ^0.8.30;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract MockContractInteractions { 
    function mockSwap(address tokenIn, address tokenOut, uint256 amountIn, uint256 amountOutMin) external returns (uint256 amountOut) {
        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
        IERC20(tokenOut).transfer(msg.sender, amountOut);
        return amountOut;
    }

    function mockDeposit(address token, uint256 amount) external {
        IERC20(token).transferFrom(msg.sender, address(this), amount);
    }

    function mockWithdraw(address token, uint256 amount) external {
        IERC20(token).transfer(msg.sender, amount);
    }
}
