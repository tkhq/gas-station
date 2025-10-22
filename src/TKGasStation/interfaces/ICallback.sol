import {IBatchExecution} from "./IBatchExecution.sol";

interface ICallback {
    function callback(
        address _sender,
        address _target,
        bool _success,
        IBatchExecution.Call memory _call,
        IBatchExecution.Call[] memory _calls
    ) external returns (bool success, IBatchExecution.Call[] memory _calls);
}
