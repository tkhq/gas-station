// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

interface IERC20Old {
    //function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 value) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 value) external returns (bool); // not normal
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

contract MockERC20ApproveNotRevert is IERC20Old {
    string private _name;
    string private _symbol;

    bool public approveAllowed;

    function setApproveAllowed(bool _approveAllowed) external {
        approveAllowed = _approveAllowed;
    }

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

    function transfer(address to, uint256 amount) public returns (bool) {
        require(_balances[msg.sender] >= amount, "Insufficient balance");
        _balances[msg.sender] -= amount;
        _balances[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        require(_allowances[from][msg.sender] >= amount, "Insufficient allowance");
        require(_balances[from] >= amount, "Insufficient balance");

        _allowances[from][msg.sender] -= amount;
        _balances[from] -= amount;
        _balances[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        // if approve fails for some reason, return false?
        if (!approveAllowed) {
            return false;
        }
        _allowances[msg.sender][spender] = amount;
        return true;
    }
}
