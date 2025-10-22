contract SessionBasedGasStation {
    using SafeERC20 for IERC20;

    error NotOwner();
    error NotSigned();

    address public owner;
    address public immutable gasToken;

    constructor(address _owner, address _gasToken) {
        owner = _owner;
        gasToken = _gasToken;
    }

    mapping(address => bytes) public signedSessions;

    function setSession(address _target, bytes calldata _session) external {
        signedSessions[_target] = _session;
    }

    function removeSession(address _target) external {
        signedSessions[_target] = bytes("");
    }

    function execute(address _target, uint256 _gasAmount, bytes calldata _session) external {
        if (msg.sender != owner) {
            revert NotOwner();
        }
        bytes memory signature = signedSessions[_target];
        if (signature.length == 0) {
            revert NotSigned();
        }
        IERC20(gasToken).safeTransferFrom(_target, address(this), _gasAmount);
    }

    function withdrawGas() external {
        if (msg.sender != owner) {
            revert NotOwner();
        }
        IERC20(gasToken).safeTransfer(owner, IERC20(gasToken).balanceOf(address(this)));
    }
}
