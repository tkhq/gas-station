// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/Gassy/Gassy.sol";
import "../src/Gassy/GassyStation.sol";
import "../test/Mocks/MockERC20.sol";

contract GassyTest is Test {
    GassyStation public gassyStation;
    Gassy public gassy;
    MockERC20 public mockToken;
    
    address public paymaster = makeAddr("paymaster");
    address public targetContract = makeAddr("targetContract");
    uint256 public constant USER_PRIVATE_KEY = 0xAAAAAA;
    address payable public user; 
    
    function setUp() public {
        // Deploy GassyStation
        gassyStation = new GassyStation();
        user = payable(vm.addr(USER_PRIVATE_KEY)); // 0x3545A2F3928d5b21E71a790FB458F4AE03306C55
        
        // Deploy Mock ERC20
        mockToken = new MockERC20("Test Token", "TEST");
        
        vm.deal(paymaster, 10 ether);

        gassy = gassyStation.gassy();
        
    }
    
    function testGassyStationDeployment() public {
        assertTrue(address(gassyStation) != address(0));
    }
    
    function testGassyCreation() public {
        assertTrue(address(gassy) != address(0));
        assertEq(gassy.paymaster(), address(gassyStation));
    }

    function delegateGassy() internal {

        Vm.SignedDelegation memory signedDelegation = vm.signDelegation(address(gassy), USER_PRIVATE_KEY);

        vm.prank(paymaster);
        vm.attachDelegation(signedDelegation);
        vm.stopPrank();
    }


    function _sign(
        uint256 _privateKey, 
        GassyStation _gassyStation,
        address _outputContract,
        uint256 _ethAmount,
        bytes memory _arguments,
        uint256 _nonce
    )
        internal
        returns (bytes memory)
    {
        address signer = vm.addr(_privateKey);
        vm.startPrank(signer);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(_privateKey, _gassyStation.hashExecution(GassyStation.Execution({
                outputContract: _outputContract,
                ethAmount: _ethAmount,
                arguments: _arguments,
                nonce: _nonce
            })));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();
        return signature;
    }
    

    function testGassyBinding() public {
            assertEq(address(user).code.length, 0);
            delegateGassy();

            bytes memory code = address(user).code;
            assertGt(code.length, 0);
            assertEq(Gassy(user).paymaster(), address(gassyStation));
    }


    function testGassyExecuteSendERC20() public {
            
            mockToken.mint(user, 20 * 10**18);
            address receiver = makeAddr("receiver");

            delegateGassy();
            uint256 nonce = Gassy(user).nonce();
            bytes memory signature = _sign(USER_PRIVATE_KEY, gassyStation, address(mockToken), 0, abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10**18), nonce);

            bool success;
            bytes memory result;
            vm.prank(paymaster);
            (success, result) = gassyStation.execute(
                address(mockToken), 
                0, 
                abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10**18), 
                nonce, 
                signature
            );
            vm.stopPrank();
            uint recieverBalance = mockToken.balanceOf(receiver);
            assertEq(recieverBalance, 10 * 10**18);
            assertEq(success, true);
    }

    
    function testGassyExecuteSendETH() public {

            delegateGassy();

            address receiver = makeAddr("receiver");
            vm.deal(user, 2 ether);
            assertEq(address(receiver).balance, 0 ether);
            
            uint256 nonce = Gassy(user).nonce();
            bytes memory signature = _sign(USER_PRIVATE_KEY, gassyStation, receiver, 1 ether, "", nonce);
            
            bool success;
            bytes memory result;
            vm.startPrank(paymaster);
            (success, result) = gassyStation.execute(receiver, 1 ether, "", nonce, signature);
            
            assertEq(success, true);
            assertEq(result.length, 0); // returns 0x00

            vm.stopPrank();

            assertEq(address(receiver).balance, 1 ether);
            // Note: In tests, the test contract pays gas, not the pranked address
            // The paymaster is just the msg.sender, but gas comes from the test contract
    }
    

}
