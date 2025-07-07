// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

contract MockContractInteraction {

    error Msg(address a);
    error Msg2(uint256 a);
    constructor() {
    }
    mapping(address => uint256) public balances;
    function add(uint256 amount) public {
        balances[msg.sender] += amount;
    }
    function sub(uint256 amount) public {
        balances[msg.sender] -= amount;
    }
    function getBalance(address account) public view returns (uint256) {
        return balances[account];
    }
    
    // Payable function to test ETH transfers
    function addWithETH(uint256 amount) public payable {
        balances[msg.sender] += amount;
        // The ETH sent with this transaction is now in this contract
    }
    
    // Function to get the contract's ETH balance
    function getETHBalance() public view returns (uint256) {
        return address(this).balance;
    }
    
    // Function to withdraw ETH
    function withdrawETH() public {
        (bool success, ) = msg.sender.call{value: address(this).balance}("");
        require(success, "Withdrawal failed");
    }
}