// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "forge-std/console2.sol";
import {TKGasDelegate} from "../src/TKGasStation/TKGasDelegate.sol";

interface IImmutableCreate2Factory {
    function safeCreate2(bytes32 _salt, bytes calldata _initCode)
        external
        payable
        returns (address _deploymentAddress);
}

contract DeployTKGasDelegate is Script {
    address private constant IMMUTABLE_CREATE2_FACTORY = 0x0000000000FFe8B47B3e2130213B802212439497;

    function run() external {
        uint256 _deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(_deployerPrivateKey);

        // Construct salt: mined for gas efficiency, should be 0x000066a00056CD44008768E2aF00696e19A30084
        bytes32 _salt = 0x00000000000000000000000000000000000000002c74f4786c5192ee33f500c0;

        // Get the creation code (TKGasDelegate has no constructor args)
        bytes memory _initCode = type(TKGasDelegate).creationCode;

        // Deploy via ImmutableCreate2Factory
        IImmutableCreate2Factory _factory = IImmutableCreate2Factory(IMMUTABLE_CREATE2_FACTORY);
        address _delegate = _factory.safeCreate2(_salt, _initCode);
        console2.log("TKGasDelegate deployed at:", _delegate);

        vm.stopBroadcast();
    }
}
