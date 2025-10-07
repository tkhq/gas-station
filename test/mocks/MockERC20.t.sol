// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "solady/tokens/ERC20.sol";

contract MockERC20 is ERC20 {
    string private _name;
    string private _symbol;

    constructor(string memory _tokenName, string memory _tokenSymbol) {
        _name = _tokenName;
        _symbol = _tokenSymbol;
    }

    function name() public view override returns (string memory) {
        return _name;
    }

    function symbol() public view override returns (string memory) {
        return _symbol;
    }

    // Arbitrary mint function for testing
    function mint(address to, uint256 amount) external returns (uint256) {
        _mint(to, amount);
        return amount;
    }

    function returnPlusHoldings(uint256 plus) external view returns (uint256) {
        return plus + balanceOf(msg.sender);
    }
}
