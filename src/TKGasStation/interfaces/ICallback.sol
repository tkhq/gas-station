import {IBatchExecution} from "./IBatchExecution.sol";

interface ICallback {
    function callback(
        address _sender,
        address _target,
        IBatchExecution.Call memory _call,
        bool _callSuccess,
        bytes memory _result,
        IBatchExecution.Call[] memory _calls
    ) external returns (bool success, IBatchExecution.Call[] memory _calls);
}
