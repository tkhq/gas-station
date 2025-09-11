// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/Gassy/Gassy.sol";
import "../src/Gassy/GassyStation.sol";
import "../src/Gassy/IBatchExecution.sol";
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

        // Delegate gassy for the user
        _delegateGassy(USER_PRIVATE_KEY);
    }

    function testGassyStationDeployment() public view {
        assertTrue(address(gassyStation) != address(0));
    }

    function testGassyCreation() public view {
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
        uint128 _nonce,
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

    function testGassyDelegationInit() public view {
        bytes memory code = address(user).code;
        assertGt(code.length, 0);
        assertEq(Gassy(user).paymaster(), address(gassyStation));
        assertEq(Gassy(user).nonce(), 0);
        assertEq(Gassy(user).timeboxedCounter(), 0);
    }

    function testGassyExecuteSendERC20() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        uint128 nonce = Gassy(user).nonce();
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
        uint128 nonce = Gassy(user).nonce();
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

        address receiver = makeAddr("receiver");
        vm.deal(user, 2 ether);
        assertEq(address(receiver).balance, 0 ether);

        uint128 nonce = Gassy(user).nonce();
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

        uint128 nonce = Gassy(user).nonce();
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

        uint128 nonce = Gassy(user).nonce();

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

        uint128 nonce = Gassy(user).nonce();
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

        uint128 nonce = Gassy(user).nonce();
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

        _delegateGassy(user2PrivateKey);

        uint128 nonce = Gassy(user).nonce();
        uint128 nonce2 = Gassy(user2).nonce();
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

        uint128 nonce = Gassy(user).nonce();

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

    function testGassyExecuteBatch() public {
        mockToken.mint(user, 50 * 10 ** 18);
        address receiver1 = makeAddr("receiver1");
        address receiver2 = makeAddr("receiver2");

        uint128 nonce = Gassy(user).nonce();

        // Create batch execution with multiple transfers
        IBatchExecution.Execution[] memory executions = new IBatchExecution.Execution[](2);
        executions[0] = IBatchExecution.Execution({
            nonce: nonce,
            outputContract: address(mockToken),
            ethAmount: 0,
            arguments: abi.encodeWithSelector(mockToken.transfer.selector, receiver1, 10 * 10 ** 18)
        });
        executions[1] = IBatchExecution.Execution({
            nonce: nonce,
            outputContract: address(mockToken),
            ethAmount: 0,
            arguments: abi.encodeWithSelector(mockToken.transfer.selector, receiver2, 15 * 10 ** 18)
        });

        // Create signature for batch execution
        bytes memory signature = _signBatch(USER_PRIVATE_KEY, gassyStation, nonce, executions);

        bool success;
        bytes[] memory results;

        vm.prank(paymaster);
        (success, results) = gassyStation.executeBatch(nonce, executions, signature);
        vm.stopPrank();

        // Verify batch execution succeeded
        assertEq(success, true);

        // Verify token transfers
        assertEq(mockToken.balanceOf(receiver1), 10 * 10 ** 18);
        assertEq(mockToken.balanceOf(receiver2), 15 * 10 ** 18);
        assertEq(mockToken.balanceOf(user), 25 * 10 ** 18); // 50 - 10 - 15

        // Verify nonce incremented
        assertEq(Gassy(user).nonce(), nonce + 1);
    }

    function _signBatch(
        uint256 _privateKey,
        GassyStation _gassyStation,
        uint128 _nonce,
        IBatchExecution.Execution[] memory _executions
    ) internal returns (bytes memory) {
        address signer = vm.addr(_privateKey);
        vm.startPrank(signer);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_privateKey, _gassyStation.hashBatchExecution(_nonce, _executions));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();
        return signature;
    }

    function testGassyExecuteBatchSizeLimit() public {
        mockToken.mint(user, 1000 * 10 ** 18);
        address receiver = makeAddr("receiver");

        uint128 nonce = Gassy(user).nonce();

        // Create batch execution with 51 transactions (exceeds MAX_BATCH_SIZE of 50)
        IBatchExecution.Execution[] memory executions = new IBatchExecution.Execution[](51);
        for (uint256 i = 0; i < 51; i++) {
            executions[i] = IBatchExecution.Execution({
                nonce: nonce,
                outputContract: address(mockToken),
                ethAmount: 0,
                arguments: abi.encodeWithSelector(mockToken.transfer.selector, receiver, 1 * 10 ** 18)
            });
        }

        // Create signature for batch execution
        bytes memory signature = _signBatch(USER_PRIVATE_KEY, gassyStation, nonce, executions);

        // Should revert due to batch size limit
        vm.prank(paymaster);
        vm.expectRevert();
        gassyStation.executeBatch(nonce, executions, signature);
        vm.stopPrank();
    }

    function testGassyExecuteBatchMaxSizeAllowed() public {
        mockToken.mint(user, 1000 * 10 ** 18);
        address receiver = makeAddr("receiver");

        uint128 nonce = Gassy(user).nonce();

        // Create batch execution with exactly 50 transactions (MAX_BATCH_SIZE)
        IBatchExecution.Execution[] memory executions = new IBatchExecution.Execution[](50);
        for (uint256 i = 0; i < 50; i++) {
            executions[i] = IBatchExecution.Execution({
                nonce: nonce,
                outputContract: address(mockToken),
                ethAmount: 0,
                arguments: abi.encodeWithSelector(mockToken.transfer.selector, receiver, 1 * 10 ** 18)
            });
        }

        // Create signature for batch execution
        bytes memory signature = _signBatch(USER_PRIVATE_KEY, gassyStation, nonce, executions);

        bool success;
        bytes[] memory results;

        // Should succeed with exactly MAX_BATCH_SIZE transactions
        vm.prank(paymaster);
        (success, results) = gassyStation.executeBatch(nonce, executions, signature);
        vm.stopPrank();

        // Verify batch execution succeeded
        assertEq(success, true);

        // Verify token transfers
        assertEq(mockToken.balanceOf(receiver), 50 * 10 ** 18);
        assertEq(mockToken.balanceOf(user), 950 * 10 ** 18); // 1000 - 50

        // Verify nonce incremented
        assertEq(Gassy(user).nonce(), nonce + 1);
    }

    function testGassyBurnNonce() public {
        uint128 nonce = Gassy(user).nonce();

        // Create signature for burning nonce
        bytes memory signature = _signBurnNonce(USER_PRIVATE_KEY, gassyStation, nonce);

        // Burn the nonce
        vm.prank(paymaster);
        gassyStation.burnNonce(nonce, signature);
        vm.stopPrank();

        // Verify nonce was incremented
        assertEq(Gassy(user).nonce(), nonce + 1);
    }

    function testGassyBurnNonceRevertsInvalidNonce() public {
        uint128 nonce = Gassy(user).nonce();

        // Create signature for burning wrong nonce
        bytes memory signature = _signBurnNonce(
            USER_PRIVATE_KEY,
            gassyStation,
            nonce + 1 // Wrong nonce
        );

        // Should revert when trying to burn wrong nonce
        vm.prank(paymaster);
        vm.expectRevert();
        gassyStation.burnNonce(nonce + 1, signature);
        vm.stopPrank();

        // Verify nonce was not changed
        assertEq(Gassy(user).nonce(), nonce);
    }

    function testGassyBurnNonceThenExecute() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        uint128 nonce = Gassy(user).nonce();

        // Burn the nonce first
        bytes memory burnSignature = _signBurnNonce(USER_PRIVATE_KEY, gassyStation, nonce);

        vm.prank(paymaster);
        gassyStation.burnNonce(nonce, burnSignature);
        vm.stopPrank();

        // Verify nonce was incremented
        assertEq(Gassy(user).nonce(), nonce + 1);

        // Now try to execute with the burned nonce - should fail
        bytes memory executeSignature = _sign(
            USER_PRIVATE_KEY,
            gassyStation,
            nonce, // This nonce was burned
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
        );

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        vm.expectRevert();
        (success, result) = gassyStation.execute(
            nonce,
            address(mockToken),
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18),
            executeSignature
        );
        vm.stopPrank();

        // Verify no tokens were transferred
        assertEq(mockToken.balanceOf(receiver), 0);
    }

    function testGassyDirectBurnNonce() public {
        uint128 nonce = Gassy(user).nonce();

        // User can directly burn their own nonce without signature
        vm.startPrank(user, user); // msg.sender = user, tx.origin = user
        Gassy(user).burnNonce(nonce);
        vm.stopPrank();

        // Verify nonce was incremented
        assertEq(Gassy(user).nonce(), nonce + 1);
    }

    function testGassyDirectBurnNonceRevertsInvalidNonce() public {
        uint128 nonce = Gassy(user).nonce();

        // User tries to burn wrong nonce - should revert
        vm.startPrank(user, user); // msg.sender = user, tx.origin = user
        vm.expectRevert();
        Gassy(user).burnNonce(nonce + 1);
        vm.stopPrank();

        // Verify nonce was not changed
        assertEq(Gassy(user).nonce(), nonce);
    }

    function testGassyDirectBurnNonceThenExecute() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        uint128 nonce = Gassy(user).nonce();

        // User directly burns their own nonce
        vm.startPrank(user, user); // msg.sender = user, tx.origin = user
        Gassy(user).burnNonce(nonce);
        vm.stopPrank();

        // Verify nonce was incremented
        assertEq(Gassy(user).nonce(), nonce + 1);

        // Now try to execute with the burned nonce - should fail
        bytes memory executeSignature = _sign(
            USER_PRIVATE_KEY,
            gassyStation,
            nonce, // This nonce was burned
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
        );

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        vm.expectRevert();
        (success, result) = gassyStation.execute(
            nonce,
            address(mockToken),
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18),
            executeSignature
        );
        vm.stopPrank();

        // Verify no tokens were transferred
        assertEq(mockToken.balanceOf(receiver), 0);
    }

    function testGassyDirectBurnNonceVsSignatureBurn() public {
        uint128 nonce = Gassy(user).nonce();

        // Method 1: Direct burn (user calls their own contract)
        vm.startPrank(user, user); // msg.sender = user, tx.origin = user
        Gassy(user).burnNonce(nonce);
        vm.stopPrank();

        uint128 nonceAfterDirect = Gassy(user).nonce();
        assertEq(nonceAfterDirect, nonce + 1);

        // Method 2: Signature burn (through GassyStation)
        uint128 newNonce = Gassy(user).nonce();
        bytes memory signature = _signBurnNonce(USER_PRIVATE_KEY, gassyStation, newNonce);

        vm.prank(paymaster);
        gassyStation.burnNonce(newNonce, signature);
        vm.stopPrank();

        uint128 nonceAfterSignature = Gassy(user).nonce();
        assertEq(nonceAfterSignature, newNonce + 1);

        // Both methods should work and increment nonce
        assertEq(nonceAfterSignature, nonceAfterDirect + 1);
    }

    function _signBurnNonce(uint256 _privateKey, GassyStation _gassyStation, uint128 _nonce)
        internal
        returns (bytes memory)
    {
        address signer = vm.addr(_privateKey);
        vm.startPrank(signer);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_privateKey, _gassyStation.hashBurnNonce(_nonce));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();
        return signature;
    }

    function _signTimeboxed(
        uint256 _privateKey,
        GassyStation _gassyStation,
        uint128 _counter,
        uint128 _deadline,
        address _sender,
        address _outputContract
    ) internal returns (bytes memory) {
        address signer = vm.addr(_privateKey);
        vm.startPrank(signer);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(_privateKey, _gassyStation.hashTimeboxedExecution(_counter, _deadline, _sender, _outputContract));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();
        return signature;
    }

    function _signTimeboxedArbitrary(
        uint256 _privateKey,
        GassyStation _gassyStation,
        uint128 _counter,
        uint128 _deadline,
        address _sender
    ) internal returns (bytes memory) {
        address signer = vm.addr(_privateKey);
        vm.startPrank(signer);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(_privateKey, _gassyStation.hashArbitraryTimeboxedExecution(_counter, _deadline, _sender));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();
        return signature;
    }

    function _signBurnTimeboxedCounter(uint256 _privateKey, GassyStation _gassyStation, uint128 _counter)
        internal
        returns (bytes memory)
    {
        address signer = vm.addr(_privateKey);
        vm.startPrank(signer);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_privateKey, _gassyStation.hashBurnTimeboxedCounter(_counter));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();
        return signature;
    }

    // ============ TIMEBOXED EXECUTION TESTS ============

    function testExecuteTimeboxed() public {
        uint128 counter = Gassy(user).timeboxedCounter();
        uint128 deadline = uint128(block.timestamp + 1 hours);
        uint256 ethAmount = 0.1 ether;
        address reciever = makeAddr("reciever");
        bytes memory executionData = ""; //abi.encodeWithSignature("");

        // Fund the user contract
        vm.deal(user, 1 ether);

        // Sign the timeboxed execution
        bytes memory signature = _signTimeboxed(USER_PRIVATE_KEY, gassyStation, counter, deadline, paymaster, reciever);

        // Execute timeboxed transaction
        vm.startPrank(paymaster);
        (bool success,) =
            gassyStation.executeTimeboxed(counter, deadline, reciever, ethAmount, executionData, signature);
        vm.stopPrank();

        assertTrue(success);
        assertEq(Gassy(user).timeboxedCounter(), 0); // Counter should NOT increment
        assertEq(reciever.balance, ethAmount);
        assertEq(user.balance, 1 ether - ethAmount);
    }

    function testExecuteTimeboxedArbitrary() public {
        uint128 counter = Gassy(user).timeboxedCounter();
        uint128 deadline = uint128(block.timestamp + 1 hours);
        uint256 ethAmount = 0.1 ether;
        address reciever = makeAddr("reciever");
        bytes memory executionData = ""; //abi.encodeWithSignature("");

        // Fund the user contract
        vm.deal(user, 1 ether);

        // Sign the timeboxed execution
        bytes memory signature = _signTimeboxedArbitrary(USER_PRIVATE_KEY, gassyStation, counter, deadline, paymaster);

        // Execute timeboxed transaction
        vm.startPrank(paymaster);
        (bool success,) =
            gassyStation.executeTimeboxedArbitrary(counter, deadline, reciever, ethAmount, executionData, signature);
        vm.stopPrank();

        assertTrue(success);
        assertEq(Gassy(user).timeboxedCounter(), 0); // Counter should NOT increment
        assertEq(reciever.balance, ethAmount);
        assertEq(user.balance, 1 ether - ethAmount);
    }

    function testExecuteTimeboxedArbitraryRevertsDeadlineExceeded() public {
        uint128 counter = Gassy(user).timeboxedCounter();
        uint128 deadline = uint128(block.timestamp + 1 hours);
        uint256 ethAmount = 0.1 ether;
        address reciever = makeAddr("reciever");
        bytes memory executionData = ""; //abi.encodeWithSignature("");

        // Fund the user contract
        vm.deal(user, 1 ether);

        // Sign the timeboxed execution
        bytes memory signature = _signTimeboxedArbitrary(USER_PRIVATE_KEY, gassyStation, counter, deadline, paymaster);

        // Execute timeboxed transaction
        vm.startPrank(paymaster);
        vm.expectRevert(); //invalid signature
        gassyStation.executeTimeboxedArbitrary(
            counter,
            deadline + 1, // makes the signature unable to be validated
            reciever,
            ethAmount,
            executionData,
            signature
        );
        vm.warp(deadline + 1);
        vm.expectRevert(GassyStation.DeadlineExceeded.selector); //deadline exceeded
        gassyStation.executeTimeboxedArbitrary(counter, deadline, reciever, ethAmount, executionData, signature);
        vm.stopPrank();
    }

    function testExecuteBatchTimeboxedArbitrary() public {
        uint128 counter = Gassy(user).timeboxedCounter();
        uint128 deadline = uint128(block.timestamp + 1 hours);

        // Fund the user contract
        vm.deal(user, 1 ether);

        // Create batch executions
        IBatchExecution.Execution[] memory executions = new IBatchExecution.Execution[](2);
        address receiver1 = makeAddr("receiver1");
        address receiver2 = makeAddr("receiver2");

        executions[0] =
            IBatchExecution.Execution({nonce: 0, outputContract: receiver1, ethAmount: 0.05 ether, arguments: ""});
        executions[1] =
            IBatchExecution.Execution({nonce: 1, outputContract: receiver2, ethAmount: 0.05 ether, arguments: ""});

        // Sign the arbitrary timeboxed execution
        bytes memory signature = _signTimeboxedArbitrary(USER_PRIVATE_KEY, gassyStation, counter, deadline, paymaster);

        // Execute batch timeboxed transaction
        vm.startPrank(paymaster);
        (bool success, bytes[] memory results) =
            gassyStation.executeBatchTimeboxedArbitrary(counter, deadline, executions, signature);
        vm.stopPrank();

        assertTrue(success);
        assertEq(results.length, 2);
        assertEq(Gassy(user).timeboxedCounter(), 0); // Counter should NOT increment
        assertEq(receiver1.balance, 0.05 ether);
        assertEq(receiver2.balance, 0.05 ether);
        assertEq(user.balance, 1 ether - 0.1 ether);
    }

    function testBurnTimeboxedCounter() public {
        uint128 counter = 0;

        // Sign the burn timeboxed counter
        bytes memory signature = _signBurnTimeboxedCounter(USER_PRIVATE_KEY, gassyStation, counter);

        // Burn timeboxed counter
        vm.startPrank(paymaster);
        gassyStation.burnTimeboxedCounter(counter, signature);
        vm.stopPrank();

        assertEq(Gassy(user).timeboxedCounter(), 1); // Counter should increment
    }

    function testDirectBurnTimeboxedCounter() public {
        uint128 counter = 0;

        vm.startPrank(paymaster);
        vm.expectRevert();
        Gassy(user).burnTimeboxedCounter(counter);
        vm.stopPrank();

        // Burn timeboxed counter
        vm.startPrank(user);
        vm.expectRevert(); // user is not the tx.origin
        Gassy(user).burnTimeboxedCounter(counter);
        vm.stopPrank();

        // Burn timeboxed counter
        vm.startPrank(user, user);
        Gassy(user).burnTimeboxedCounter(counter);
        vm.stopPrank();

        assertEq(Gassy(user).timeboxedCounter(), 1); // Counter should increment

        // Burn timeboxed counter
        vm.startPrank(user, user);
        vm.expectRevert(); // can't burn twice
        Gassy(user).burnTimeboxedCounter(counter);
        vm.stopPrank();
    }
}
