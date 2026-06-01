// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "forge-std/console2.sol";
import {TKGasDelegate} from "../src/TKGasStation/TKGasDelegate.sol";

interface IImmutableCreate2Factory {
    function safeCreate2(bytes32 _salt, bytes calldata _initCode) external payable returns (address _deploymentAddress);
}

contract DeployTKGasDelegate is Script {
    address private constant IMMUTABLE_CREATE2_FACTORY = 0x0000000000FFe8B47B3e2130213B802212439497;
    address private constant EXPECTED_TK_GAS_DELEGATE = 0x2a31eF110e4Cdb9C332aA1d8633510214299c48B;

    function run() external {
        uint256 _deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        bytes32 _salt = 0x0000000000000000000000000000000000000000000000000000004761737379;
        bytes memory _initCode = type(TKGasDelegate).creationCode;
        address _computedDelegate = vm.computeCreate2Address(_salt, keccak256(_initCode), IMMUTABLE_CREATE2_FACTORY);

        require(
            IMMUTABLE_CREATE2_FACTORY.code.length > 0,
            "ImmutableCreate2Factory missing on this chain; deploy 0x0000000000FFe8B47B3e2130213B802212439497 first"
        );
        require(_computedDelegate == EXPECTED_TK_GAS_DELEGATE, "TKGasDelegate canonical address mismatch");

        if (_computedDelegate.code.length > 0) {
            console2.log("TKGasDelegate already deployed at:", _computedDelegate);
            return;
        }

        vm.startBroadcast(_deployerPrivateKey);

        // Deploy via ImmutableCreate2Factory
        IImmutableCreate2Factory _factory = IImmutableCreate2Factory(IMMUTABLE_CREATE2_FACTORY);
        address _delegate = _factory.safeCreate2(_salt, _initCode);
        console2.log("TKGasDelegate deployed at:", _delegate);

        vm.stopBroadcast();
    }
}
