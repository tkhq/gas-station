// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {TKGasStation} from "../src/TKGasStation/TKGasStation.sol";
import {TKGasDelegate} from "../src/TKGasStation/TKGasDelegate.sol";
import {ITKGasDelegate} from "../src/TKGasStation/ITKGasDelegate.sol";
import "../test/Mocks/MockERC20.sol";

contract TKGasStationTest is Test {
    TKGasStation public tkGasStation;
    TKGasDelegate public tkGasDelegate;
    MockERC20 public mockToken;

    address public paymaster = makeAddr("paymaster");
    uint256 public constant USER_PRIVATE_KEY = 0xAAAAAA;
    address payable public user;

    function setUp() public {
        // Deploy TKGasDelegate first
        tkGasDelegate = new TKGasDelegate();

        // Deploy TKGasStation with TKGasDelegate address
        tkGasStation = new TKGasStation(address(tkGasDelegate));

        user = payable(vm.addr(USER_PRIVATE_KEY));

        // Deploy Mock ERC20
        mockToken = new MockERC20("Test Token", "TEST");

        vm.deal(paymaster, 10 ether);
        vm.deal(user, 5 ether);

        // Delegate TKGasDelegate for the user
        _delegateGasStation(USER_PRIVATE_KEY);
    }

    function _delegateGasStation(uint256 _userPrivateKey) internal {
        Vm.SignedDelegation memory signedDelegation =
            vm.signDelegation(payable(address(tkGasDelegate)), _userPrivateKey);

        vm.prank(paymaster);
        vm.attachDelegation(signedDelegation);
        vm.stopPrank();
    }

    function _sign(
        uint256 _privateKey,
        address payable _publicKey,
        uint128 _nonce,
        address _outputContract,
        uint256 _ethAmount,
        bytes memory _arguments
    ) internal returns (bytes memory) {
        address signer = vm.addr(_privateKey);
        vm.startPrank(signer);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            _privateKey, TKGasDelegate(_publicKey).hashExecution(_nonce, _outputContract, _ethAmount, _arguments)
        );
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();
        return signature;
    }

    function testERC20Transfer() public {
        console.log("=== TKGasStation ERC20 TRANSFER TEST ===");

        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        // Get current nonce
        uint128 nonce = TKGasDelegate(user).nonce();

        // Create signature
        bytes memory signature = _sign(
            USER_PRIVATE_KEY,
            user,
            nonce,
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
        );

        // Execute ERC20 transfer through TKGasStation
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();

        (bool success, bytes memory result) = tkGasStation.execute(
            user,
            nonce,
            address(mockToken),
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18),
            signature
        );

        uint256 gasAfter = gasleft();
        uint256 gasUsed = gasBefore - gasAfter;

        assertTrue(success);
        assertEq(mockToken.balanceOf(receiver), 10 * 10 ** 18);

        console.log("TKGasStation ERC20 transfer gas: %s", gasUsed);
        console.log("");
    }

    function testETHTransfer() public {
        console.log("=== TKGasStation ETH TRANSFER TEST ===");

        address payable receiver = payable(makeAddr("receiver"));
        uint256 transferAmount = 1 ether;

        // Fund the user with ETH
        vm.deal(user, 2 ether);
        assertEq(address(receiver).balance, 0 ether);

        // Get current nonce and create signature
        uint128 nonce = ITKGasDelegate(user).nonce();
        bytes memory signature = _sign(USER_PRIVATE_KEY, user, nonce, receiver, transferAmount, "");

        // Execute ETH transfer through TKGasStation
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        (bool success, bytes memory result) = tkGasStation.execute(user, nonce, receiver, transferAmount, "", signature);

        uint256 gasAfter = gasleft();
        uint256 gasUsed = gasBefore - gasAfter;

        assertTrue(success);
        assertEq(result.length, 0); // ETH transfers return empty result
        assertEq(address(receiver).balance, transferAmount);

        console.log("TKGasStation ETH transfer gas: %s", gasUsed);
        console.log("");
    }
    
    function testNotDelegatedRevert() public {
        
        // Create a new user that is NOT delegated
        uint256 newUserPrivateKey = 0xBBBBBB;
        address payable newUser = payable(vm.addr(newUserPrivateKey));
        
        mockToken.mint(newUser, 10 * 10 ** 18);
        address receiver = makeAddr("receiver");

        uint128 nonce = ITKGasDelegate(user).nonce(); // Use nonce 0 for new user
        bytes memory signature = _sign(
            USER_PRIVATE_KEY, // Use the delegated user's private key to create signature
            user, // Use the delegated user's address for hashExecution
            nonce,
            address(mockToken),
            0, // No ETH amount
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 5 * 10 ** 18)
        );

        // This should revert because newUser is not delegated
        vm.prank(paymaster);
        vm.expectRevert(TKGasStation.NotDelegated.selector);
        tkGasStation.execute(
            newUser,
            nonce,
            address(mockToken),
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 5 * 10 ** 18),
            signature
        );

    }
}
