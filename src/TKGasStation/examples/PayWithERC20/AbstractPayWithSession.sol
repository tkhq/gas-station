pragma solidity ^0.8.30;

import {AbstractPayWithERC20GasStation} from "./AbstractPayWithERC20GasStation.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ITKGasDelegate} from "../../interfaces/ITKGasDelegate.sol";

abstract contract AbstractPayWithSession is AbstractPayWithERC20GasStation {
    using SafeERC20 for IERC20;

    error InvalidSignature();

    struct Session {
        uint128 counter;
        uint32 deadline;
        bytes signature; // must be 65 bytes
            //address sender; // this
            //address output; // the payment token
    }

    mapping(address => bytes) public sessions;

    constructor(address _tkGasDelegate, address _paymentToken, address _owner)
        AbstractPayWithERC20GasStation(_tkGasDelegate, _paymentToken, _owner)
    {}

    function setSession(address _user, uint128 _counter, uint32 _deadline, bytes calldata _signature) external {
        if (_signature.length != 65) {
            revert InvalidSignature();
        }
        bytes32 hash = ITKGasDelegate(_user).hashSessionExecution(_counter, _deadline, address(this), paymentToken);
        if (ITKGasDelegate(_user).validateSignature(hash, _signature)) {
            sessions[_user] = abi.encode(Session({counter: _counter, deadline: _deadline, signature: _signature}));
        }
    }

    function removeSession() external {
        delete sessions[msg.sender];
    }

    function _reimburseGasCost(address _token, uint256 _amount, address _from, address _recipient)
        internal
        override
        returns (uint256)
    {
        uint256 toReimburse = _getExchangeRate(_token, _amount);
        Session memory session = abi.decode(sessions[_from], (Session));
        if (session.signature.length != 65) {
            // also checks if null
            revert InvalidSignature();
        }
        bytes memory transactionData = abi.encodeWithSelector(IERC20.transfer.selector, _amount, _recipient);
        bytes memory data = abi.encode(session.signature, session.counter, session.deadline, transactionData);
        ITKGasDelegate(_from).executeSession(paymentToken, 0, data);
        return toReimburse;
    }
}
