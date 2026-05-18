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
    address private constant EXPECTED_TK_GAS_STATION = 0x1cBBD58E521e1133F09E2Ba207e3e75c4DB404D5;

    function run() external {
        uint256 _deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address _delegate = vm.envAddress("TK_GAS_DELEGATE");
        bytes32 _salt = 0x0000000000000000000000000000000000000000000000000000004761737379;

        require(
            IMMUTABLE_CREATE2_FACTORY.code.length > 0,
            "ImmutableCreate2Factory missing on this chain; deploy 0x0000000000FFe8B47B3e2130213B802212439497 first"
        );

        // Get the creation code with constructor arguments
        bytes memory _creationCode = type(TKGasStation).creationCode;
        bytes memory _constructorArgs = abi.encode(_delegate);
        bytes memory _initCode = abi.encodePacked(_creationCode, _constructorArgs);
        address _computedStation = vm.computeCreate2Address(_salt, keccak256(_initCode), IMMUTABLE_CREATE2_FACTORY);

        require(_delegate.code.length > 0, "TK_GAS_DELEGATE has no code on this chain");
        require(
            _computedStation == EXPECTED_TK_GAS_STATION,
            "TK_GAS_DELEGATE does not produce the canonical TKGasStation address"
        );

        if (_computedStation.code.length > 0) {
            console2.log("TKGasStation already deployed at:", _computedStation);
            return;
        }

        vm.startBroadcast(_deployerPrivateKey);

        // Deploy via ImmutableCreate2Factory (anyone can deploy to this address with the same salt)
        IImmutableCreate2Factory _factory = IImmutableCreate2Factory(IMMUTABLE_CREATE2_FACTORY);
        address _station = _factory.safeCreate2(_salt, _initCode);
        console2.log("TKGasStation deployed at:", _station);

        vm.stopBroadcast();
    }
}
