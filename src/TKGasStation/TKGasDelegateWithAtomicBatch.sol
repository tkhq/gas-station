import {TKGasDelegate} from "./TKGasDelegate.sol";

import {ICallback} from "./interfaces/ICallback.sol";

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
    }

    function _executeAtomicBatch(address _sender, address _callback, IBatchExecution.Call[] memory _calls) internal {
        for (uint256 i = 0; i < _calls.length; i++) {
            IBatchExecution.Call memory call = _calls[i];
            (bool success, bytes memory result) = call.to.call{value: call.value}(call.data);
            if (!success) {
                revert ExecutionFailed();
            }
            (bool callbackSuccess, _calls) =
                ICallback(_callback).callback(_sender, address(this), success, call, _calls);
            if (!callbackSuccess) {
                revert CallbackFailed();
            }
        }
    }
}
