// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

// Non standard ERC20 
interface IERC20NotNormal {
    //function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 value) external;
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 value) external; // not normal 
    function transferFrom(address from, address to, uint256 value) external;
}

contract MockUSDT is IERC20NotNormal {
    string private _name;
    string private _symbol;

    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;

    constructor(string memory _tokenName, string memory _tokenSymbol) {
        _name = _tokenName;
        _symbol = _tokenSymbol;
    }

    function name() public view returns (string memory) {
        return _name;
    }

    function symbol() public view returns (string memory) {
        return _symbol;
    }

    // Arbitrary mint function for testing
    function mint(address to, uint256 amount) external {
        _balances[to] += amount;
    }

    function balanceOf(address account) public view returns (uint256) {
        return _balances[account];
    }

    function allowance(address owner, address spender) public view returns (uint256) {
        return _allowances[owner][spender];
    }

    function transfer(address to, uint256 amount) public {
        require(_balances[msg.sender] >= amount, "Insufficient balance");
        _balances[msg.sender] -= amount;
        _balances[to] += amount;
    }

    function approve(address spender, uint256 amount) public {
        // copying logic from usdt's mainnet implementation

        // To change the approve amount you first have to reduce the addresses`
        // allowance to zero by calling `approve(_spender, 0)` if it is not
        // already 0 to mitigate the race condition described here:
        // https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729

        //require(!((_value != 0) && (allowed[msg.sender][_spender] != 0)));

        require(!((amount != 0) && (_allowances[msg.sender][spender] != 0)));

        _allowances[msg.sender][spender] = amount; 
    }

    function transferFrom(address from, address to, uint256 amount) public {
        require(_allowances[from][msg.sender] >= amount, "Insufficient allowance");
        require(_balances[from] >= amount, "Insufficient balance");
        
        _allowances[from][msg.sender] -= amount;
        _balances[from] -= amount;
        _balances[to] += amount;
    }
}
