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
}