// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {TKGasStation} from "../src/TKGasStation/TKGasStation.sol";
import {TKGasDelegate} from "../src/TKGasStation/TKGasDelegate.sol";
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
        Vm.SignedDelegation memory signedDelegation = vm.signDelegation(payable(address(tkGasDelegate)), _userPrivateKey);

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
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(_privateKey, TKGasDelegate(_publicKey).hashExecution(_nonce, _outputContract, _ethAmount, _arguments));
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
            nonce, address(mockToken), abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18), signature
        );
        
        uint256 gasAfter = gasleft();
        uint256 gasUsed = gasBefore - gasAfter;

        assertTrue(success);
        assertEq(mockToken.balanceOf(receiver), 10 * 10 ** 18);
        
        console.log("TKGasStation ERC20 transfer gas: %s", gasUsed);
        console.log("");
    }
/*
    function testETHTransfer() public {
        console.log("=== TKGasStation ETH TRANSFER TEST ===");
        
        address payable receiver = payable(makeAddr("receiver"));
        uint256 transferAmount = 1 ether;

        uint256 gasBefore = gasleft();
        
        // Execute ETH transfer through TKGasStation
        vm.prank(paymaster);
        (bool success, bytes memory result) = tkGasStation.execute(
            user,
            user,
            abi.encodeWithSelector(tkGasDelegate.execute.selector, address(mockToken),abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18))
        );
        
        uint256 gasAfter = gasleft();
        uint256 gasUsed = gasBefore - gasAfter;

        assertTrue(success);
        assertEq(receiver.balance, transferAmount);
        
        console.log("TKGasStation ETH transfer gas: %s", gasUsed);
        console.log("");
    }

    function testNotDelegatedRevert() public {
        console.log("=== TKGasStation NOT DELEGATED TEST ===");
        
        // Create a new user that is NOT delegated
        uint256 newUserPrivateKey = 0xBBBBBB;
        address payable newUser = payable(vm.addr(newUserPrivateKey));
        
        mockToken.mint(newUser, 10 * 10 ** 18);
        address receiver = makeAddr("receiver");

        // This should revert because newUser is not delegated
        vm.prank(paymaster);
        vm.expectRevert(TKGasStation.NotDelegated.selector);
        tkGasStation.execute(
            newUser,
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 5 * 10 ** 18)
        );
        
        console.log("TKGasStation correctly reverts for non-delegated user");
        console.log("");
    }

    function testDebugDelegation() public {
        console.log("=== DEBUG DELEGATION ===");
        console.log("User address:", user);
        console.log("User code size:", user.code.length);
        console.log("TKGasStation address:", address(tkGasStation));
        console.log("TKGasDelegate address:", address(tkGasDelegate));
        
        // Check if user is delegated
        bool isDelegated = tkGasStation.isDelegated(user);
        console.log("Is user delegated:", isDelegated);
        
        // Check what the delegation actually created
        if (user.code.length > 0) {
            console.log("User has code, length:", user.code.length);
            console.logBytes(user.code);
            
            // Extract the delegated address from the code
            bytes memory code = user.code;
            address delegatedTo;
            assembly {
                delegatedTo := shr(96, mload(add(code, 23)))
            }
            console.log("Delegated to address:", delegatedTo);
            console.log("TKGasStation address:", address(tkGasStation));
            console.log("Addresses match:", delegatedTo == address(tkGasStation));
        } else {
            console.log("User has no code");
        }
    }
    */
}
