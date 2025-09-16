// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "solady/tokens/ERC20.sol";

contract MockERC20 is ERC20 {
    string private _name;
    string private _symbol;

    constructor(string memory name, string memory symbol) {
        _name = name;
        _symbol = symbol;
    }

    function name() public view override returns (string memory) {
        return _name;
    }

    function symbol() public view override returns (string memory) {
        return _symbol;
    }

    // Arbitrary mint function for testing
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function returnPlusHoldings(uint256 plus) external view returns (uint256) {
        return plus + balanceOf(msg.sender);
    }
}
