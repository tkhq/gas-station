// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "forge-std/console2.sol";
import {TKGasStation} from "../src/TKGasStation/TKGasStation.sol";

interface IImmutableCreate2Factory {
    function safeCreate2(bytes32 _salt, bytes calldata _initCode) external payable returns (address _deploymentAddress);
}

contract DeployTKGasStation is Script {
    address private constant IMMUTABLE_CREATE2_FACTORY = 0x0000000000FFe8B47B3e2130213B802212439497;

    function run() external {
        uint256 _deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address _delegate = 0x000066a00056CD44008768E2aF00696e19A30084; // TKGasDelegate 
        bytes32 _salt = 0x0000000000000000000000000000000000000000c6b3f42ca51eca44cb120242; // should end up as 0x00984aC3c498A35A8d00004200f2001100bC0000

        vm.startBroadcast(_deployerPrivateKey);

        // Get the creation code with constructor arguments
        bytes memory _creationCode = type(TKGasStation).creationCode;
        bytes memory _constructorArgs = abi.encode(_delegate);
        bytes memory _initCode = abi.encodePacked(_creationCode, _constructorArgs);

        // Deploy via ImmutableCreate2Factory (anyone can deploy to this address with the same salt)
        IImmutableCreate2Factory _factory = IImmutableCreate2Factory(IMMUTABLE_CREATE2_FACTORY);
        address _station = _factory.safeCreate2(_salt, _initCode);
        console2.log("TKGasStation deployed at:", _station);

        vm.stopBroadcast();
    }
}


