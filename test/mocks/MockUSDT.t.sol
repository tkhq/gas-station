// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "solady/tokens/ERC20.sol";

contract MockUSDT is ERC20 {
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
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function approve(address spender, uint256 amount) public virtual override returns (bool) {
            // copying logic from usdt's mainnet implementation
            
            // To change the approve amount you first have to reduce the addresses`
            // allowance to zero by calling `approve(_spender, 0)` if it is not
            // already 0 to mitigate the race condition described here:
            // https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
            
            //require(!((_value != 0) && (allowed[msg.sender][_spender] != 0)));

            require(!((amount != 0) && (allowance(msg.sender, spender) != 0)));
            
            _approve(msg.sender, spender, amount);
            return true; 
    }

}
