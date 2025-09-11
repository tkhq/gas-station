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

    function _delegateGassy(uint256 _userPrivateKey) internal {
        Vm.SignedDelegation memory signedDelegation = vm.signDelegation(address(gassy), _userPrivateKey);

        vm.prank(paymaster);
        vm.attachDelegation(signedDelegation);
        vm.stopPrank();
    }

    function _sign(
        uint256 _privateKey,
        GassyStation _gassyStation,
        uint256 _nonce,
        address _outputContract,
        uint256 _ethAmount,
        bytes memory _arguments
    ) internal returns (bytes memory) {
        address signer = vm.addr(_privateKey);
        vm.startPrank(signer);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(_privateKey, _gassyStation.hashExecution(_nonce, _outputContract, _ethAmount, _arguments));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();
        return signature;
    }

    function testGassyBinding() public {
        assertEq(address(user).code.length, 0);
        _delegateGassy(USER_PRIVATE_KEY);

        bytes memory code = address(user).code;
        assertGt(code.length, 0);
        assertEq(Gassy(user).paymaster(), address(gassyStation));
    }

    function testGassyExecuteSendERC20() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        _delegateGassy(USER_PRIVATE_KEY);
        uint256 nonce = Gassy(user).nonce();
        bytes memory signature = _sign(
            USER_PRIVATE_KEY,
            gassyStation,
            nonce,
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
        );

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        (success, result) = gassyStation.execute(
            nonce,
            address(mockToken),
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18),
            signature
        );
        vm.stopPrank();
        uint256 recieverBalance = mockToken.balanceOf(receiver);
        assertEq(recieverBalance, 10 * 10 ** 18);
        assertEq(success, true);
        assertEq(Gassy(user).nonce(), nonce + 1);
    }

    function testGassyExecuteCheckReturnValue() public {
        mockToken.mint(user, 20 * 10 ** 18);
        _delegateGassy(USER_PRIVATE_KEY);
        uint256 nonce = Gassy(user).nonce();
        bytes memory signature = _sign(
            USER_PRIVATE_KEY,
            gassyStation,
            nonce,
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.returnPlusHoldings.selector, 10 * 10 ** 18)
        );

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        (success, result) = gassyStation.execute(
            nonce,
            address(mockToken),
            abi.encodeWithSelector(mockToken.returnPlusHoldings.selector, 10 * 10 ** 18),
            signature
        );
        vm.stopPrank();
        assertEq(success, true);
        assertEq(result.length, 32);
        assertEq(abi.decode(result, (uint256)), 30 * 10 ** 18);
        assertEq(Gassy(user).nonce(), nonce + 1);
    }

    function testGassyExecuteSendETH() public {
        mockToken.mint(user, 20 * 10 ** 18);

        _delegateGassy(USER_PRIVATE_KEY);

        address receiver = makeAddr("receiver");
        vm.deal(user, 2 ether);
        assertEq(address(receiver).balance, 0 ether);

        uint256 nonce = Gassy(user).nonce();
        bytes memory signature = _sign(USER_PRIVATE_KEY, gassyStation, nonce, receiver, 1 ether, "");

        bool success;
        bytes memory result;
        vm.startPrank(paymaster);
        (success, result) = gassyStation.execute(nonce, receiver, 1 ether, "", signature);

        assertEq(success, true);
        assertEq(result.length, 0); // returns 0x00

        vm.stopPrank();

        assertEq(address(receiver).balance, 1 ether);
        assertEq(Gassy(user).nonce(), nonce + 1);

        // Note: In tests, the test contract pays gas, not the pranked address
        // The paymaster is just the msg.sender, but gas comes from the test contract
    }

    function testGassyExecuteRevertsInvalidNonce() public {
        mockToken.mint(user, 20 * 10 ** 18);

        _delegateGassy(USER_PRIVATE_KEY);
        uint256 nonce = Gassy(user).nonce();
        bytes memory signature = _sign(
            USER_PRIVATE_KEY,
            gassyStation,
            nonce + 1,
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.returnPlusHoldings.selector, 10 * 10 ** 18)
        );

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        vm.expectRevert();
        (success, result) = gassyStation.execute(
            nonce + 1,
            address(mockToken),
            abi.encodeWithSelector(mockToken.returnPlusHoldings.selector, 10 * 10 ** 18),
            signature
        );
        vm.stopPrank();
    }

    function testGassyExecuteRevertsNotThroughStation() public {
        mockToken.mint(user, 20 * 10 ** 18);

        _delegateGassy(USER_PRIVATE_KEY);
        uint256 nonce = Gassy(user).nonce();
        bytes memory signature = _sign(
            USER_PRIVATE_KEY,
            gassyStation,
            nonce,
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.returnPlusHoldings.selector, 10 * 10 ** 18)
        );

        bool success;
        bytes memory result;
        vm.prank(makeAddr("notPaymaster"));
        vm.expectRevert();
        (success, result) = Gassy(user).execute(
            nonce, address(mockToken), 0, abi.encodeWithSelector(mockToken.returnPlusHoldings.selector, 10 * 10 ** 18)
        );
        vm.stopPrank();
    }

    function testGassyExecuteRevertsFailedExecution() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        _delegateGassy(USER_PRIVATE_KEY);
        uint256 nonce = Gassy(user).nonce();
        bytes memory signature = _sign(
            USER_PRIVATE_KEY,
            gassyStation,
            nonce,
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 30 * 10 ** 18)
        );

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        vm.expectRevert();
        (success, result) = gassyStation.execute(
            nonce,
            address(mockToken),
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 30 * 10 ** 18),
            signature
        );
        vm.stopPrank();
    }

    function testGassyExecuteRevertsInvalidSignature() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        _delegateGassy(USER_PRIVATE_KEY);
        uint256 nonce = Gassy(user).nonce();
        bytes memory signature = _sign(
            USER_PRIVATE_KEY,
            gassyStation,
            nonce,
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 20 * 10 ** 18)
        );

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        vm.expectRevert();
        (success, result) = gassyStation.execute(
            nonce,
            address(mockToken),
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18),
            signature
        );
        vm.stopPrank();
    }

    function testGassyEachUserHasDifferentNonce() public {
        mockToken.mint(user, 20 * 10 ** 18);
        uint256 user2PrivateKey = 0xBBBBBB;
        address payable user2 = payable(vm.addr(user2PrivateKey));

        _delegateGassy(USER_PRIVATE_KEY);
        _delegateGassy(user2PrivateKey);

        uint256 nonce = Gassy(user).nonce();
        uint256 nonce2 = Gassy(user2).nonce();
        assertEq(nonce, 0);
        assertEq(nonce2, 0);

        bytes memory signature = _sign(
            USER_PRIVATE_KEY,
            gassyStation,
            nonce,
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.returnPlusHoldings.selector, 10 * 10 ** 18)
        );

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        (success, result) = gassyStation.execute(
            nonce,
            address(mockToken),
            abi.encodeWithSelector(mockToken.returnPlusHoldings.selector, 10 * 10 ** 18),
            signature
        );
        vm.stopPrank();

        assertEq(Gassy(user).nonce(), nonce + 1);
        assertEq(Gassy(user2).nonce(), nonce2);
    }

    function testGassyExecuteRevertsNonceReuse() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        _delegateGassy(USER_PRIVATE_KEY);
        uint256 nonce = Gassy(user).nonce();
        
        // Create signature for first execution
        bytes memory signature = _sign(
            USER_PRIVATE_KEY,
            gassyStation,
            nonce,
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
        );

        bool success;
        bytes memory result;
        
        // First execution should succeed
        vm.prank(paymaster);
        (success, result) = gassyStation.execute(
            nonce,
            address(mockToken),
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18),
            signature
        );
        vm.stopPrank();
        
        assertEq(success, true);
        assertEq(Gassy(user).nonce(), nonce + 1);
        
        // Second execution with same nonce should revert
        vm.prank(paymaster);
        vm.expectRevert();
        (success, result) = gassyStation.execute(
            nonce, // Reusing the same nonce
            address(mockToken),
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18),
            signature
        );
        vm.stopPrank();
    }
}
