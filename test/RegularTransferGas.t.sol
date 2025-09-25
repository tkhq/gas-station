// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../test/Mocks/MockERC20.sol";

contract RegularTransferGasTest is Test {
    MockERC20 public mockToken;
    
    uint256 public constant USER_PRIVATE_KEY = 0xAAAAAA;
    address payable public user;

    function setUp() public {
        user = payable(vm.addr(USER_PRIVATE_KEY));
        
        // Deploy Mock ERC20
        mockToken = new MockERC20("Test Token", "TEST");
        
        vm.deal(user, 5 ether);
    }

    function testRegularERC20TransferGas() public {
        console.log("=== REGULAR ERC20 TRANSFER GAS ANALYSIS ===");
        
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");
        
        // Prepare arguments outside of gas measurement
        bytes memory arguments = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        
        _executeRegularERC20TransferWithGas(address(mockToken), arguments);
        
        console.log("");
    }

    function testRegularETHTransferGas() public {
        console.log("=== REGULAR ETH TRANSFER GAS ANALYSIS ===");
        
        vm.deal(user, 5 ether);
        address receiver = makeAddr("receiver");
        
        _executeRegularETHTransferWithGas(receiver, 1 ether);
        
        console.log("");
    }

    function _executeRegularERC20TransferWithGas(address _token, bytes memory _arguments) internal {
        vm.startPrank(user);
        uint256 gasBefore = gasleft();
        (bool success,) = _token.call(_arguments);
        uint256 gasAfter = gasleft();
        uint256 gasUsed = gasBefore - gasAfter;
        vm.stopPrank();
        
        require(success, "ERC20 transfer failed");
        console.log("Regular ERC20 transfer gas: %s", gasUsed);
    }

    function _executeRegularETHTransferWithGas(address _receiver, uint256 _amount) internal {
        vm.startPrank(user);
        uint256 gasBefore = gasleft();
        (bool success,) = _receiver.call{value: _amount}("");
        uint256 gasAfter = gasleft();
        uint256 gasUsed = gasBefore - gasAfter;
        vm.stopPrank();
        
        require(success, "ETH transfer failed");
        console.log("Regular ETH transfer gas: %s", gasUsed);
    }
}
