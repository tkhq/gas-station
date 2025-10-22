import {TKGasDelegate} from "./TKGasDelegate.sol";

import {ICallback} from "./interfaces/ICallback.sol";

import {IBatchExecution} from "./interfaces/IBatchExecution.sol";

contract TKGasDelegateWithAtomicBatch is TKGasDelegate {
    error CallbackFailed();

    bytes32 private constant ATOMIC_BATCH_TYPEHASH =
        keccak256("AtomicBatch(uint128 counter,uint32 deadline,address sender, address callback)");

    function executeAtomicBatch(
        bytes calldata _signature,
        bytes calldata _counterBytes,
        bytes calldata _deadlineBytes,
        address _callback,
        IBatchExecution.Call[] memory _calls
    ) external {
        // todo validation
        _executeAtomicBatch(msg.sender, _callback, _calls);
    }

    function _executeAtomicBatch(address _sender, address _callback, IBatchExecution.Call[] memory _calls) internal {
        for (uint256 i = 0; i < _calls.length; i++) {
            IBatchExecution.Call memory call = _calls[i];
            (bool success, bytes memory result) = call.to.call{value: call.value}(call.data);
            (bool callbackSuccess, IBatchExecution.Call[] memory updatedCalls) =
                ICallback(_callback).callback(_sender, address(this), call, success, result, _calls);
            _calls = updatedCalls;
            if (!callbackSuccess) {
                revert CallbackFailed();
            }
        }
    }
}
