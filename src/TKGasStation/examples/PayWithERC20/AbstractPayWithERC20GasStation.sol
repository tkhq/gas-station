// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AbstractGasStation} from "../AbstractGasStation.sol";
import {IBatchExecution} from "../../interfaces/IBatchExecution.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

abstract contract AbstractPayWithERC20GasStation is AbstractGasStation, Ownable {
    using SafeERC20 for IERC20;

    address public paymentToken;

    constructor(address _tkGasDelegate, address _paymentToken, address _owner)
        AbstractGasStation(_tkGasDelegate)
        Ownable(_owner)
    {
        paymentToken = _paymentToken;
    }

    /* Admin functions */

    function setPaymentToken(address _paymentToken) external onlyOwner {
        paymentToken = _paymentToken;
    }

    function withdraw(address _token, address _destination) external onlyOwner {
        // allow any token to be withdrawn in case payment token was changed
        IERC20(_token).safeTransfer(_destination, IERC20(_token).balanceOf(address(this)));
    }

    /* Required virtual functions */

    function _getExchangeRate(address _token, uint256 _amount) internal virtual returns (uint256);

    function _reimburseGasCost(address _token, uint256 _amount, address _from, address _recipient)
        internal
        virtual
        returns (uint256);

    function _getReimbursementRecipient(address, /* _token */ uint256, /* _amount */ address /* _from */ )
        internal
        virtual
        returns (address)
    {
        // in this example, the reimbursement recipient is the contract itself
        // pratically, this should be overridden to whatever the customer wants
        // or this could be overridden to tx.origin (the user who initiated the transaction)
        return address(this);
    }

    /* Execute functions */

    // Override execute functions
    function executeReturns(address _target, address _to, uint256 _ethAmount, bytes calldata _data)
        public
        virtual
        override
        returns (bytes memory)
    {
        uint256 before = gasleft();
        bytes memory result = super.executeReturns(_target, _to, _ethAmount, _data);
        uint256 gasUsed = before - gasleft();
        _reimburseGasCost(paymentToken, gasUsed, _target, _getReimbursementRecipient(paymentToken, gasUsed, _target));
        return result;
    }

    function execute(address _target, address _to, uint256 _ethAmount, bytes calldata _data) public virtual override {
        uint256 before = gasleft();
        super.execute(_target, _to, _ethAmount, _data);
        uint256 gasUsed = before - gasleft();
        _reimburseGasCost(paymentToken, gasUsed, _target, _getReimbursementRecipient(paymentToken, gasUsed, _target));
    }

    // Override approveThenExecute functions
    function approveThenExecuteReturns(
        address _target,
        address _to,
        uint256 _ethAmount,
        address _erc20,
        address _spender,
        uint256 _approveAmount,
        bytes calldata _data
    ) public virtual override returns (bytes memory) {
        uint256 before = gasleft();
        bytes memory result =
            super.approveThenExecuteReturns(_target, _to, _ethAmount, _erc20, _spender, _approveAmount, _data);
        uint256 gasUsed = before - gasleft();
        _reimburseGasCost(paymentToken, gasUsed, _target, _getReimbursementRecipient(paymentToken, gasUsed, _target));
        return result;
    }

    function approveThenExecute(
        address _target,
        address _to,
        uint256 _ethAmount,
        address _erc20,
        address _spender,
        uint256 _approveAmount,
        bytes calldata _data
    ) public virtual override {
        uint256 before = gasleft();
        super.approveThenExecute(_target, _to, _ethAmount, _erc20, _spender, _approveAmount, _data);
        uint256 gasUsed = before - gasleft();
        _reimburseGasCost(paymentToken, gasUsed, _target, _getReimbursementRecipient(paymentToken, gasUsed, _target));
    }

    // Override batch execute functions
    function executeBatchReturns(address _target, IBatchExecution.Call[] calldata _calls, bytes calldata _data)
        public
        virtual
        override
        returns (bytes[] memory)
    {
        uint256 before = gasleft();
        bytes[] memory results = super.executeBatchReturns(_target, _calls, _data);
        uint256 gasUsed = before - gasleft();
        _reimburseGasCost(paymentToken, gasUsed, _target, _getReimbursementRecipient(paymentToken, gasUsed, _target));
        return results;
    }

    function executeBatch(address _target, IBatchExecution.Call[] calldata _calls, bytes calldata _data)
        public
        virtual
        override
    {
        uint256 before = gasleft();
        super.executeBatch(_target, _calls, _data);
        uint256 gasUsed = before - gasleft();
        _reimburseGasCost(paymentToken, gasUsed, _target, _getReimbursementRecipient(paymentToken, gasUsed, _target));
    }

    function burnNonce(address _targetEoA, bytes calldata _signature, uint128 _nonce) public virtual override {
        uint256 before = gasleft();
        super.burnNonce(_targetEoA, _signature, _nonce);
        uint256 gasUsed = before - gasleft();
        _reimburseGasCost(
            paymentToken, gasUsed, _targetEoA, _getReimbursementRecipient(paymentToken, gasUsed, _targetEoA)
        );
    }
}
