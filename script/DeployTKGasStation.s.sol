// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "forge-std/console2.sol";
import {TKGasStation as TKGasStationV1} from "../src/TKGasStation/TKGasStation.sol";
import {TKGasStation as TKGasStationV2} from "../src/TKGasStation2/TKGasStation.sol";

contract DeployTKGasStation is Script {
    function run() external {
        uint256 _deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(_deployerPrivateKey);

        TKGasStationV1 _v1 = new TKGasStationV1();
        //TKGasStationV2 _v2 = new TKGasStationV2();

        vm.stopBroadcast();

        console2.log("TKGasStationV1 deployed at:", address(_v1));
        //console2.log("TKGasStationV2 deployed at:", address(_v2));
    }
}
