// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {TKGasDelegate} from "../src/TKGasStation/TKGasDelegate.sol";
import {IBatchExecution} from "../src/TKGasStation/interfaces/IBatchExecution.sol";
import "../test/mocks/MockERC20.sol";

contract TKGasDelegateTest is Test {
    TKGasDelegate public tkGasStation;
    MockERC20 public mockToken;

    address public paymaster = makeAddr("paymaster");
    address public targetContract = makeAddr("targetContract");
    uint256 public constant USER_PRIVATE_KEY = 0xAAAAAA;
    address payable public user;

    function setUp() public {
        // Deploy TKGasStation
        tkGasStation = new TKGasDelegate();
        user = payable(vm.addr(USER_PRIVATE_KEY)); // 0x3545A2F3928d5b21E71a790FB458F4AE03306C55

        // Deploy Mock ERC20
        mockToken = new MockERC20("Test Token", "TEST");

        vm.deal(paymaster, 10 ether);

        // Delegate TKGasDelegate for the user
        _delegateGasStation(USER_PRIVATE_KEY);
    }

    function testGassyStationDeployment() public view {
        assertTrue(payable(address(tkGasStation)) != address(0));
    }

    function testGassyCreation() public view {
        assertTrue(payable(address(tkGasStation)) != address(0));
    }

    function _delegateGasStation(uint256 _userPrivateKey) internal {
        Vm.SignedDelegation memory signedDelegation = vm.signDelegation(payable(address(tkGasStation)), _userPrivateKey);

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

    function testGassyDelegationInit() public view {
        bytes memory code = address(user).code;
        assertGt(code.length, 0);
        //assertEq(TKGasDelegate(user).paymaster(), payable(address(tkGasStation)));
        assertEq(TKGasDelegate(user).nonce(), 0);
        assertEq(TKGasDelegate(user).sessionCounter(), 0);
    }

    function testGassyExecuteSendERC20() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        uint128 nonce = TKGasDelegate(user).nonce();
        bytes memory signature = _sign(
            USER_PRIVATE_KEY,
            user,
            nonce,
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
        );

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        (success, result) = TKGasDelegate(user).execute(
            signature,
            nonce,
            address(mockToken),
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
        );
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        uint256 recieverBalance = mockToken.balanceOf(receiver);
        assertEq(recieverBalance, 10 * 10 ** 18);
        assertEq(success, true);
        assertEq(TKGasDelegate(user).nonce(), nonce + 1);

        // Log gas analysis
        console.log("=== TKGasStation ERC20 Transfer Analysis ===");
        console.log("Total Gas Used: %s", gasUsed);
    }

    function testGassyExecuteCheckReturnValue() public {
        mockToken.mint(user, 20 * 10 ** 18);
        uint128 nonce = TKGasDelegate(user).nonce();
        bytes memory signature = _sign(
            USER_PRIVATE_KEY,
            user,
            nonce,
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.returnPlusHoldings.selector, 10 * 10 ** 18)
        );

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        (success, result) = TKGasDelegate(user).execute(
            signature,
            nonce,
            address(mockToken),
            abi.encodeWithSelector(mockToken.returnPlusHoldings.selector, 10 * 10 ** 18)
        );
        vm.stopPrank();
        assertEq(success, true);
        assertEq(result.length, 32);
        assertEq(abi.decode(result, (uint256)), 30 * 10 ** 18);
        assertEq(TKGasDelegate(user).nonce(), nonce + 1);
    }

    function testGassyExecuteSendETH() public {
        mockToken.mint(user, 20 * 10 ** 18);

        address receiver = makeAddr("receiver");
        vm.deal(user, 2 ether);
        assertEq(address(receiver).balance, 0 ether);

        uint128 nonce = TKGasDelegate(user).nonce();
        bytes memory signature = _sign(USER_PRIVATE_KEY, user, nonce, receiver, 1 ether, "");

        bool success;
        bytes memory result;
        vm.startPrank(paymaster);
        uint256 gasBefore = gasleft();
        (success, result) = TKGasDelegate(user).execute(signature, nonce, receiver, 1 ether, "");
        uint256 gasUsed = gasBefore - gasleft();

        assertEq(success, true);
        assertEq(result.length, 0); // returns 0x00
        vm.stopPrank();

        assertEq(address(receiver).balance, 1 ether);
        assertEq(TKGasDelegate(user).nonce(), nonce + 1);

        console.log("=== TKGasDelegate ETH Transfer Analysis ===");
        console.log("Total Gas Used: %s", gasUsed);
    }

    function testGassyExecuteRevertsInvalidNonce() public {
        mockToken.mint(user, 20 * 10 ** 18);

        uint128 nonce = TKGasDelegate(user).nonce();
        bytes memory signature = _sign(
            USER_PRIVATE_KEY,
            user,
            nonce + 1,
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.returnPlusHoldings.selector, 10 * 10 ** 18)
        );

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        vm.expectRevert();
        (success, result) = TKGasDelegate(user).execute(
            signature,
            nonce + 1,
            address(mockToken),
            abi.encodeWithSelector(mockToken.returnPlusHoldings.selector, 10 * 10 ** 18)
        );
        vm.stopPrank();
    }
    /*
    function testGassyExecuteRevertsNotThroughStation() public {
        mockToken.mint(user, 20 * 10 ** 18);

        bool success;
        bytes memory result;
        vm.prank(makeAddr("notPaymaster"));
        vm.expectRevert();
        // TKGasDelegate no longer has a public execute function
        // (success, result) = TKGasDelegate(user).execute(
        //     address(mockToken), 0, abi.encodeWithSelector(mockToken.returnPlusHoldings.selector, 10 * 10 ** 18)
        // );
        vm.stopPrank();
    }
    */

    function testGassyExecuteRevertsFailedExecution() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        uint128 nonce = TKGasDelegate(user).nonce();
        bytes memory signature = _sign(
            USER_PRIVATE_KEY,
            user,
            nonce,
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 30 * 10 ** 18)
        );

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        vm.expectRevert();
        (success, result) = TKGasDelegate(user).execute(
            signature,
            nonce,
            address(mockToken),
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 30 * 10 ** 18)
        );
        vm.stopPrank();
    }

    function testGassyExecuteRevertsInvalidSignature() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        uint128 nonce = TKGasDelegate(user).nonce();
        bytes memory signature = _sign(
            USER_PRIVATE_KEY,
            user,
            nonce,
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 20 * 10 ** 18)
        );

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        vm.expectRevert();
        (success, result) = TKGasDelegate(user).execute(
            signature,
            nonce,
            address(mockToken),
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
        );
        vm.stopPrank();
    }

    function testGassyEachUserHasDifferentNonce() public {
        mockToken.mint(user, 20 * 10 ** 18);
        uint256 user2PrivateKey = 0xBBBBBB;
        address payable user2 = payable(vm.addr(user2PrivateKey));

        _delegateGasStation(user2PrivateKey);

        uint128 nonce = TKGasDelegate(user).nonce();
        uint128 nonce2 = TKGasDelegate(user).nonce();
        assertEq(nonce, 0);
        assertEq(nonce2, 0);

        bytes memory signature = _sign(
            USER_PRIVATE_KEY,
            user,
            nonce,
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.returnPlusHoldings.selector, 10 * 10 ** 18)
        );

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        (success, result) = TKGasDelegate(user).execute(
            signature,
            nonce,
            address(mockToken),
            abi.encodeWithSelector(mockToken.returnPlusHoldings.selector, 10 * 10 ** 18)
        );
        vm.stopPrank();

        assertEq(TKGasDelegate(user).nonce(), nonce + 1);
        assertEq(TKGasDelegate(user2).nonce(), nonce2);
    }

    function testGassyExecuteRevertsNonceReuse() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        uint128 nonce = TKGasDelegate(user).nonce();

        // Create signature for first execution
        bytes memory signature = _sign(
            USER_PRIVATE_KEY,
            user,
            nonce,
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
        );

        bool success;
        bytes memory result;

        // First execution should succeed
        vm.prank(paymaster);
        (success, result) = TKGasDelegate(user).execute(
            signature,
            nonce,
            address(mockToken),
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
        );
        vm.stopPrank();

        assertEq(success, true);
        assertEq(TKGasDelegate(user).nonce(), nonce + 1);

        // Second execution with same nonce should revert
        vm.prank(paymaster);
        vm.expectRevert();
        (success, result) = TKGasDelegate(user).execute(
            signature,
            nonce, // Reusing the same nonce
            address(mockToken),
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
        );
        vm.stopPrank();
    }

    function testGassyExecuteBatch() public {
        mockToken.mint(user, 50 * 10 ** 18);
        address receiver1 = makeAddr("receiver1");
        address receiver2 = makeAddr("receiver2");

        uint128 nonce = TKGasDelegate(user).nonce();

        // Create batch execution with multiple transfers
        IBatchExecution.Call[] memory executions = new IBatchExecution.Call[](2);
        executions[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, receiver1, 10 * 10 ** 18)
        });
        executions[1] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, receiver2, 15 * 10 ** 18)
        });

        // Create signature for batch execution
        bytes memory signature = _signBatch(USER_PRIVATE_KEY, user, nonce, executions);

        bool success;
        bytes[] memory results;

        vm.prank(paymaster);
        (success, results) = TKGasDelegate(user).executeBatch(signature, nonce, executions);
        vm.stopPrank();

        // Verify batch execution succeeded
        assertEq(success, true);

        // Verify token transfers
        assertEq(mockToken.balanceOf(receiver1), 10 * 10 ** 18);
        assertEq(mockToken.balanceOf(receiver2), 15 * 10 ** 18);
        assertEq(mockToken.balanceOf(user), 25 * 10 ** 18); // 50 - 10 - 15

        // Verify nonce incremented
        assertEq(TKGasDelegate(user).nonce(), nonce + 1);
    }

    function testGassyExecuteBatchAttemptToChangeExecution() public {
        mockToken.mint(user, 50 * 10 ** 18);
        address receiver1 = makeAddr("receiver1");
        address receiver2 = makeAddr("receiver2");

        uint128 nonce = TKGasDelegate(user).nonce();

        // Create batch execution with multiple transfers
        IBatchExecution.Call[] memory executions = new IBatchExecution.Call[](2);
        executions[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, receiver1, 10 * 10 ** 18)
        });
        executions[1] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, receiver2, 15 * 10 ** 18)
        });

        // Create signature for batch execution
        bytes memory signature = _signBatch(USER_PRIVATE_KEY, user, nonce, executions);

        IBatchExecution.Call[] memory badExecutions = new IBatchExecution.Call[](2);
        badExecutions[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, receiver1, 20 * 10 ** 18)
        });
        badExecutions[1] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, receiver2, 15 * 10 ** 18)
        });

        bool success;
        bytes[] memory results;

        vm.prank(paymaster);
        vm.expectRevert();
        (success, results) = TKGasDelegate(user).executeBatch(signature, nonce, badExecutions);
        vm.stopPrank();

        // Verify no transfers occurred and nonce unchanged
        assertEq(mockToken.balanceOf(receiver1), 0);
        assertEq(mockToken.balanceOf(receiver2), 0);
        assertEq(mockToken.balanceOf(user), 50 * 10 ** 18);
        assertEq(TKGasDelegate(user).nonce(), nonce);
    }

    function _signBatch(
        uint256 _privateKey,
        address payable _publicKey,
        uint128 _nonce,
        IBatchExecution.Call[] memory _calls
    ) internal returns (bytes memory) {
        address signer = vm.addr(_privateKey);
        vm.startPrank(signer);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(_privateKey, TKGasDelegate(_publicKey).hashBatchExecution(_nonce, _calls));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();
        return signature;
    }

    function testGassyExecuteBatchSizeLimit() public {
        mockToken.mint(user, 1000 * 10 ** 18);
        address receiver = makeAddr("receiver");

        uint128 nonce = TKGasDelegate(user).nonce();

        // Create batch execution with 51 transactions (exceeds MAX_BATCH_SIZE of 50)
        IBatchExecution.Call[] memory executions = new IBatchExecution.Call[](51);
        for (uint256 i = 0; i < 51; i++) {
            executions[i] = IBatchExecution.Call({
                to: address(mockToken),
                value: 0,
                data: abi.encodeWithSelector(mockToken.transfer.selector, receiver, 1 * 10 ** 18)
            });
        }

        // Create signature for batch execution
        bytes memory signature = _signBatch(USER_PRIVATE_KEY, user, nonce, executions);

        // Should revert due to batch size limit
        vm.prank(paymaster);
        vm.expectRevert();
        TKGasDelegate(user).executeBatch(signature, nonce, executions);
        vm.stopPrank();
    }

    function testGassyExecuteBatchMaxSizeAllowed() public {
        mockToken.mint(user, 1000 * 10 ** 18);
        address receiver = makeAddr("receiver");

        uint128 nonce = TKGasDelegate(user).nonce();

        // Create batch execution with exactly 50 transactions (MAX_BATCH_SIZE)
        IBatchExecution.Call[] memory executions = new IBatchExecution.Call[](50);
        for (uint256 i = 0; i < 50; i++) {
            executions[i] = IBatchExecution.Call({
                to: address(mockToken),
                value: 0,
                data: abi.encodeWithSelector(mockToken.transfer.selector, receiver, 1 * 10 ** 18)
            });
        }

        // Create signature for batch execution
        bytes memory signature = _signBatch(USER_PRIVATE_KEY, user, nonce, executions);

        bool success;
        bytes[] memory results;

        // Should succeed with exactly MAX_BATCH_SIZE transactions
        vm.prank(paymaster);
        (success, results) = TKGasDelegate(user).executeBatch(signature, nonce, executions);
        vm.stopPrank();

        // Verify batch execution succeeded
        assertEq(success, true);

        // Verify token transfers
        assertEq(mockToken.balanceOf(receiver), 50 * 10 ** 18);
        assertEq(mockToken.balanceOf(user), 950 * 10 ** 18); // 1000 - 50

        // Verify nonce incremented
        assertEq(TKGasDelegate(user).nonce(), nonce + 1);
    }

    function testGassyBurnNonce() public {
        uint128 nonce = TKGasDelegate(user).nonce();

        // Create signature for burning nonce
        bytes memory signature = _signBurnNonce(USER_PRIVATE_KEY, user, nonce);

        // Burn the nonce
        vm.prank(paymaster);
        TKGasDelegate(user).burnNonce(signature, nonce);
        vm.stopPrank();

        // Verify nonce was incremented
        assertEq(TKGasDelegate(user).nonce(), nonce + 1);
    }

    function testGassyBurnNonceRevertsInvalidNonce() public {
        uint128 nonce = TKGasDelegate(user).nonce();

        // Create signature for burning wrong nonce
        bytes memory signature = _signBurnNonce(
            USER_PRIVATE_KEY,
            user,
            nonce + 1 // Wrong nonce
        );

        // Should revert when trying to burn wrong nonce
        vm.prank(paymaster);
        vm.expectRevert();
        TKGasDelegate(user).burnNonce(signature, nonce + 1);
        vm.stopPrank();

        // Verify nonce was not changed
        assertEq(TKGasDelegate(user).nonce(), nonce);
    }

    function testGassyBurnNonceThenExecute() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        uint128 nonce = TKGasDelegate(user).nonce();

        // Burn the nonce first
        bytes memory burnSignature = _signBurnNonce(USER_PRIVATE_KEY, user, nonce);

        vm.prank(paymaster);
        TKGasDelegate(user).burnNonce(burnSignature, nonce);
        vm.stopPrank();

        // Verify nonce was incremented
        assertEq(TKGasDelegate(user).nonce(), nonce + 1);

        // Now try to execute with the burned nonce - should fail
        bytes memory executeSignature = _sign(
            USER_PRIVATE_KEY,
            user,
            nonce, // This nonce was burned
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
        );

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        vm.expectRevert();
        (success, result) = TKGasDelegate(user).execute(
            executeSignature,
            nonce,
            address(mockToken),
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
        );
        vm.stopPrank();

        // Verify no tokens were transferred
        assertEq(mockToken.balanceOf(receiver), 0);
    }

    function testGassyDirectBurnNonce() public {
        uint128 nonce = TKGasDelegate(user).nonce();

        vm.startPrank(user, user); // msg.sender = user, tx.origin = user
        TKGasDelegate(user).burnNonce();
        vm.stopPrank();

        // Verify nonce was incremented
        assertEq(TKGasDelegate(user).nonce(), nonce + 1);
    }

    function testGassyDirectBurnNonceRevertsInvalidNonce() public {
        uint128 nonce = TKGasDelegate(user).nonce();

        // User burns their own nonce
        vm.startPrank(user, user); // msg.sender = user, tx.origin = user
        TKGasDelegate(user).burnNonce();
        vm.stopPrank();

        // Verify nonce was incremented
        assertEq(TKGasDelegate(user).nonce(), nonce + 1);
    }

    function testGassyDirectBurnNonceThenExecute() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        uint128 nonce = TKGasDelegate(user).nonce();

        // User directly burns their own nonce
        vm.startPrank(user, user); // msg.sender = user, tx.origin = user
        TKGasDelegate(user).burnNonce();
        vm.stopPrank();

        // Verify nonce was incremented
        assertEq(TKGasDelegate(user).nonce(), nonce + 1);

        // Now try to execute with the burned nonce - should fail
        bytes memory executeSignature = _sign(
            USER_PRIVATE_KEY,
            payable(address(tkGasStation)),
            nonce, // This nonce was burned
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
        );

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        vm.expectRevert();
        (success, result) = TKGasDelegate(user).execute(
            executeSignature,
            nonce,
            address(mockToken),
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
        );
        vm.stopPrank();

        // Verify no tokens were transferred
        assertEq(mockToken.balanceOf(receiver), 0);
    }

    function testGassyDirectBurnNonceVsSignatureBurn() public {
        uint128 nonce = TKGasDelegate(user).nonce();

        // Method 1: Direct burn (user calls their own contract)
        vm.startPrank(user, user); // msg.sender = user, tx.origin = user
        TKGasDelegate(user).burnNonce();
        vm.stopPrank();

        uint128 nonceAfterDirect = TKGasDelegate(user).nonce();
        assertEq(nonceAfterDirect, nonce + 1);

        // Method 2: Signature burn (through TKGasStation)
        uint128 newNonce = TKGasDelegate(user).nonce();
        bytes memory signature = _signBurnNonce(USER_PRIVATE_KEY, user, newNonce);

        vm.prank(paymaster);
        TKGasDelegate(user).burnNonce(signature, newNonce);
        vm.stopPrank();

        uint128 nonceAfterSignature = TKGasDelegate(user).nonce();
        assertEq(nonceAfterSignature, newNonce + 1);

        // Both methods should work and increment nonce
        assertEq(nonceAfterSignature, nonceAfterDirect + 1);
    }

    function _signBurnNonce(uint256 _privateKey, address payable _publicKey, uint128 _nonce)
        internal
        returns (bytes memory)
    {
        address signer = vm.addr(_privateKey);
        vm.startPrank(signer);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_privateKey, TKGasDelegate(_publicKey).hashBurnNonce(_nonce));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();
        return signature;
    }

    function _signSession(
        uint256 _privateKey,
        address payable _publicKey,
        uint128 _counter,
        uint128 _deadline,
        address _sender,
        address _outputContract
    ) internal returns (bytes memory) {
        address signer = vm.addr(_privateKey);
        vm.startPrank(signer);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            _privateKey, TKGasDelegate(_publicKey).hashSessionExecution(_counter, _deadline, _sender, _outputContract)
        );
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();
        return signature;
    }

    function _signSessionArbitrary(
        uint256 _privateKey,
        address payable _publicKey,
        uint128 _counter,
        uint128 _deadline,
        address _sender
    ) internal returns (bytes memory) {
        address signer = vm.addr(_privateKey);
        vm.startPrank(signer);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(_privateKey, TKGasDelegate(_publicKey).hashArbitrarySessionExecution(_counter, _deadline, _sender));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();
        return signature;
    }

    function _signBurnSessionCounter(uint256 _privateKey, address payable _publicKey, uint128 _counter, address _sender)
        internal
        returns (bytes memory)
    {
        address signer = vm.addr(_privateKey);
        vm.startPrank(signer);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(_privateKey, TKGasDelegate(_publicKey).hashBurnSessionCounter(_counter, _sender));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();
        return signature;
    }

    // ============ SESSION EXECUTION TESTS ============

    function testExecuteSession() public {
        uint128 counter = TKGasDelegate(user).sessionCounter();
        uint128 deadline = uint128(block.timestamp + 1 hours);
        uint256 ethAmount = 0.1 ether;
        address reciever = makeAddr("reciever");
        bytes memory executionData = ""; //abi.encodeWithSignature("");

        // Fund the user contract
        vm.deal(user, 1 ether);

        // Sign the session execution
        bytes memory signature = _signSession(USER_PRIVATE_KEY, user, counter, deadline, paymaster, reciever);

        // Execute session transaction
        vm.startPrank(paymaster);
        (bool success,) =
            TKGasDelegate(user).executeSession(signature, counter, deadline, reciever, ethAmount, executionData);
        vm.stopPrank();

        assertTrue(success);
        assertEq(TKGasDelegate(user).sessionCounter(), 0); // Counter should NOT increment
        assertEq(reciever.balance, ethAmount);
        assertEq(user.balance, 1 ether - ethAmount);
    }

    function testExecuteSessionArbitrary() public {
        uint128 counter = TKGasDelegate(user).sessionCounter();
        uint128 deadline = uint128(block.timestamp + 1 hours);
        uint256 ethAmount = 0.1 ether;
        address reciever = makeAddr("reciever");
        bytes memory executionData = ""; //abi.encodeWithSignature("");

        // Fund the user contract
        vm.deal(user, 1 ether);

        // Sign the session execution
        bytes memory signature = _signSessionArbitrary(USER_PRIVATE_KEY, user, counter, deadline, paymaster);

        // Execute session transaction
        vm.startPrank(paymaster);
        (bool success,) = TKGasDelegate(user).executeSessionArbitrary(
            signature, counter, deadline, reciever, ethAmount, executionData
        );
        vm.stopPrank();

        assertTrue(success);
        assertEq(TKGasDelegate(user).sessionCounter(), 0); // Counter should NOT increment
        assertEq(reciever.balance, ethAmount);
        assertEq(user.balance, 1 ether - ethAmount);
    }

    function testExecuteSessionArbitraryRevertsDeadlineExceeded() public {
        uint128 counter = TKGasDelegate(user).sessionCounter();
        uint128 deadline = uint128(block.timestamp + 1 hours);
        uint256 ethAmount = 0.1 ether;
        address reciever = makeAddr("reciever");
        bytes memory executionData = ""; //abi.encodeWithSignature("");

        // Fund the user contract
        vm.deal(user, 1 ether);

        // Sign the session execution
        bytes memory signature = _signSessionArbitrary(USER_PRIVATE_KEY, user, counter, deadline, paymaster);

        // Execute session transaction
        vm.startPrank(paymaster);
        vm.expectRevert(); //invalid signature
        TKGasDelegate(user).executeSessionArbitrary(
            signature,
            counter,
            deadline + 1, // makes the signature unable to be validated
            reciever,
            ethAmount,
            executionData
        );
        vm.warp(deadline + 1);
        vm.expectRevert(TKGasDelegate.DeadlineExceeded.selector); //deadline exceeded
        TKGasDelegate(user).executeSessionArbitrary(signature, counter, deadline, reciever, ethAmount, executionData);
        vm.stopPrank();
    }

    function testExecuteBatchSessionArbitrary() public {
        uint128 counter = TKGasDelegate(user).sessionCounter();
        uint128 deadline = uint128(block.timestamp + 1 hours);

        // Fund the user contract
        vm.deal(user, 1 ether);

        // Create batch executions
        IBatchExecution.Call[] memory executions = new IBatchExecution.Call[](2);
        address receiver1 = makeAddr("receiver1");
        address receiver2 = makeAddr("receiver2");

        executions[0] = IBatchExecution.Call({to: receiver1, value: 0.05 ether, data: ""});
        executions[1] = IBatchExecution.Call({to: receiver2, value: 0.05 ether, data: ""});

        // Sign the arbitrary session execution
        bytes memory signature = _signSessionArbitrary(USER_PRIVATE_KEY, user, counter, deadline, paymaster);

        // Execute batch session transaction
        vm.startPrank(paymaster);
        (bool success, bytes[] memory results) =
            TKGasDelegate(user).executeBatchSessionArbitrary(signature, counter, deadline, executions);
        vm.stopPrank();

        assertTrue(success);
        assertEq(results.length, 2);
        assertEq(TKGasDelegate(user).sessionCounter(), 0); // Counter should NOT increment
        assertEq(receiver1.balance, 0.05 ether);
        assertEq(receiver2.balance, 0.05 ether);
        assertEq(user.balance, 1 ether - 0.1 ether);
    }

    function testExecuteBatchSession() public {
        uint128 counter = TKGasDelegate(user).sessionCounter();
        uint128 deadline = uint128(block.timestamp + 1 hours);

        // Fund the user contract
        vm.deal(user, 1 ether);

        // Create batch executions with same output contract
        IBatchExecution.Call[] memory executions = new IBatchExecution.Call[](3);
        address receiver = makeAddr("receiver");

        executions[0] = IBatchExecution.Call({to: receiver, value: 0.1 ether, data: ""});
        executions[1] = IBatchExecution.Call({to: receiver, value: 0.2 ether, data: ""});
        executions[2] = IBatchExecution.Call({to: receiver, value: 0.3 ether, data: ""});

        // Sign the session execution
        bytes memory signature = _signSession(USER_PRIVATE_KEY, user, counter, deadline, paymaster, receiver);

        // Execute batch session transaction
        vm.startPrank(paymaster);
        (bool success, bytes[] memory results) =
            TKGasDelegate(user).executeBatchSession(signature, counter, deadline, receiver, executions);
        vm.stopPrank();

        assertTrue(success);
        assertEq(results.length, 3);
        assertEq(TKGasDelegate(user).sessionCounter(), 0); // Counter should NOT increment
        assertEq(receiver.balance, 0.6 ether); // 0.1 + 0.2 + 0.3
        assertEq(user.balance, 1 ether - 0.6 ether);
    }

    function testBurnSessionCounter() public {
        uint128 counter = 0;

        // Sign the burn session counter
        bytes memory signature = _signBurnSessionCounter(USER_PRIVATE_KEY, user, counter, paymaster);

        // Burn session counter
        vm.startPrank(paymaster);
        TKGasDelegate(user).burnSessionCounter(signature, counter, paymaster);
        vm.stopPrank();

        assertEq(TKGasDelegate(user).sessionCounter(), 1); // Counter should increment
    }

    function testDirectBurnSessionCounter() public {
        vm.startPrank(user, user);
        TKGasDelegate(user).burnSessionCounter();
        vm.stopPrank();

        assertEq(TKGasDelegate(user).sessionCounter(), 1); // Counter should increment

        // Burn session counter again
        vm.startPrank(user, user);
        TKGasDelegate(user).burnSessionCounter();
        vm.stopPrank();

        assertEq(TKGasDelegate(user).sessionCounter(), 2); // Counter should increment again
    }

    function testDetailedGasAnalysis() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        uint128 nonce = TKGasDelegate(user).nonce();
        bytes memory signature = _sign(
            USER_PRIVATE_KEY,
            user,
            nonce,
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
        );

        // Measure gas usage
        uint256 gasBefore = gasleft();

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        (success, result) = TKGasDelegate(user).execute(
            signature,
            nonce,
            address(mockToken),
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
        );
        vm.stopPrank();

        uint256 gasUsed = gasBefore - gasleft();

        // Verify execution
        uint256 recieverBalance = mockToken.balanceOf(receiver);
        assertEq(recieverBalance, 10 * 10 ** 18);
        assertEq(success, true);
        assertEq(TKGasDelegate(user).nonce(), nonce + 1);

        // Gas analysis
        console.log("=== TKGasStation Detailed Gas Analysis ===");
        console.log("Total Gas Used: %s", gasUsed);
    }

    function testGasAnalysisETHTransfer() public {
        // Give user some ETH
        vm.deal(user, 5 ether);
        address receiver = makeAddr("receiver");
        uint256 transferAmount = 1 ether;

        uint128 nonce = TKGasDelegate(user).nonce();
        bytes memory signature = _sign(USER_PRIVATE_KEY, user, nonce, receiver, transferAmount, "");

        // Measure gas usage
        uint256 gasBefore = gasleft();

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        (success, result) = TKGasDelegate(user).execute(signature, nonce, receiver, transferAmount, "");
        vm.stopPrank();

        uint256 gasUsed = gasBefore - gasleft();

        assertEq(receiver.balance, transferAmount);
        assertEq(success, true);
        assertEq(TKGasDelegate(user).nonce(), nonce + 1);

        // Log gas analysis
        console.log("=== TKGasStation ETH Transfer Analysis ===");
        console.log("Total Gas Used: %s", gasUsed);
        console.log("Transfer Amount: %s ETH", transferAmount / 1e18);
    }

    function testGasAnalysisWithReturnValue() public {
        mockToken.mint(user, 20 * 10 ** 18);

        uint128 nonce = TKGasDelegate(user).nonce();
        bytes memory signature = _sign(
            USER_PRIVATE_KEY,
            user,
            nonce,
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.returnPlusHoldings.selector, 100)
        );

        // Measure gas usage
        uint256 gasBefore = gasleft();

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        (success, result) = TKGasDelegate(user).execute(
            signature, nonce, address(mockToken), abi.encodeWithSelector(mockToken.returnPlusHoldings.selector, 100)
        );
        vm.stopPrank();

        uint256 gasUsed = gasBefore - gasleft();

        uint256 returnValue = abi.decode(result, (uint256));
        assertEq(returnValue, 20 * 10 ** 18 + 100);
        assertEq(success, true);
        assertEq(TKGasDelegate(user).nonce(), nonce + 1);

        // Log gas analysis
        console.log("=== TKGasStation Function with Return Value Analysis ===");
        console.log("Total Gas Used: %s", gasUsed);
        console.log("Return Value: %s", returnValue);
    }

    function testFallbackExecuteSendERC20() public {
        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        uint128 nonce = TKGasDelegate(user).nonce();
        bytes memory signature = _sign(
            USER_PRIVATE_KEY,
            user,
            nonce,
            address(mockToken),
            0,
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
        );

        console.log("=== Signature ===");
        console.log("Signature: %s", vm.toString(signature));
        console.log("=== Mock contract address ===");
        console.log("Mock contract address: %s", address(mockToken));

        // Construct calldata for fallback function
        bytes memory fallbackData = _constructFallbackCalldata(
            nonce,
            signature,
            address(mockToken),
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18)
        );

        console.log("=== Fallback Function Calldata ===");
        console.log("Calldata length: %s bytes", fallbackData.length);
        console.log("Calldata (hex): %s", vm.toString(fallbackData));
        console.log("Calldata (bytes): [%s]", _bytesToHexString(fallbackData));

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        (success, result) = user.call(fallbackData);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        uint256 receiverBalance = mockToken.balanceOf(receiver);
        assertEq(receiverBalance, 10 * 10 ** 18);
        assertEq(success, true);
        assertEq(TKGasDelegate(user).nonce(), nonce + 1);

        // Log gas analysis
        console.log("=== Fallback Function ERC20 Transfer Analysis ===");
        console.log("Total Gas Used: %s", gasUsed);
        console.log("Transfer Amount: %s", uint256(10 * 10 ** 18));
    }

    function _constructFallbackCalldata(
        uint128 _nonce,
        bytes memory _signature,
        address _outputContract,
        bytes memory _arguments
    ) internal pure returns (bytes memory) {
        // Convert nonce to bytes (1 byte for small nonce values)
        bytes memory nonceBytes = abi.encodePacked(uint8(_nonce));

        // Calculate nonce length (0-15, where 0 means 1 byte)
        // For 1 byte, we need length = 0 (since 0 means 1 byte)
        uint8 nonceLength = uint8(nonceBytes.length) - 1;

        // Construct the second byte: function selector (0x00) + nonce length
        bytes1 secondByte = bytes1(uint8(0x00) | nonceLength);

        // Construct calldata:
        // [0x00][secondByte][signature][nonce][outputContract][arguments]
        bytes memory fallbackCalldata = abi.encodePacked(
            bytes1(0x00), // Prefix
            secondByte, // Function selector + nonce length
            _signature, // 65 bytes signature
            nonceBytes, // Nonce data
            _outputContract, // 20 bytes output contract
            _arguments // Function arguments
        );

        return fallbackCalldata;
    }

    function _bytesToHexString(bytes memory _bytes) internal pure returns (string memory) {
        string memory result = "";
        for (uint256 i = 0; i < _bytes.length; i++) {
            result = string(
                abi.encodePacked(result, "0x", _toHexString(uint8(_bytes[i])), i < _bytes.length - 1 ? ", " : "")
            );
        }
        return result;
    }

    function _toHexString(uint8 _value) internal pure returns (string memory) {
        if (_value == 0) {
            return "00";
        }
        uint256 temp = _value;
        uint256 length = 0;
        while (temp != 0) {
            length++;
            temp >>= 4;
        }
        bytes memory buffer = new bytes(length);
        for (uint256 i = length; i > 0; i--) {
            buffer[i - 1] = _toHexChar(uint8(_value & 0x0f));
            _value >>= 4;
        }
        return string(buffer);
    }

    function _toHexChar(uint8 _value) internal pure returns (bytes1) {
        if (_value < 10) {
            return bytes1(uint8(bytes1("0")) + _value);
        } else {
            return bytes1(uint8(bytes1("a")) + _value - 10);
        }
    }

    function testFallbackExecuteSendETH() public {
        address receiver = makeAddr("receiver");
        uint256 ethAmount = 1 ether;

        // Give the user some ETH to transfer
        vm.deal(user, 2 ether);
        assertEq(address(receiver).balance, 0 ether);

        uint128 nonce = TKGasDelegate(user).nonce();
        bytes memory signature = _sign(
            USER_PRIVATE_KEY,
            user,
            nonce,
            receiver, // ETH transfer to receiver
            ethAmount,
            "" // Empty data for ETH transfer
        );

        console.log("=== ETH Transfer Test ===");
        console.log("Nonce: %s", nonce);
        console.log("Signature: %s", vm.toString(signature));
        console.log("ETH Amount: %s", ethAmount);
        console.log("Receiver: %s", receiver);

        // Construct calldata for fallback function with ETH
        bytes memory fallbackData = _constructFallbackCalldataWithETH(
            nonce,
            signature,
            receiver, // ETH transfer to receiver
            ethAmount,
            "" // Empty data for ETH transfer
        );

        console.log("=== Fallback Function Calldata (ETH Transfer) ===");
        console.log("Calldata length: %s bytes", fallbackData.length);
        console.log("Calldata (hex): %s", vm.toString(fallbackData));

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        (success, result) = user.call(fallbackData);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        uint256 receiverBalance = receiver.balance;
        assertEq(receiverBalance, ethAmount);
        assertEq(success, true);
        assertEq(TKGasDelegate(user).nonce(), nonce + 1);

        // Log gas analysis
        console.log("=== Fallback Function ETH Transfer Analysis ===");
        console.log("Total Gas Used: %s", gasUsed);
        console.log("ETH Amount: %s", ethAmount);
    }

    function _constructFallbackCalldataWithETH(
        uint128 _nonce,
        bytes memory _signature,
        address _outputContract,
        uint256 _ethAmount,
        bytes memory _arguments
    ) internal pure returns (bytes memory) {
        // Convert nonce to bytes (1 byte for small nonce values)
        bytes memory nonceBytes = abi.encodePacked(uint8(_nonce));

        // Calculate nonce length (0-15, where 0 means 1 byte)
        uint8 nonceLength = uint8(nonceBytes.length) - 1;

        // Construct the second byte: function selector (0x01 for executeWithValue) + nonce length
        bytes1 secondByte = bytes1(uint8(0x10) | nonceLength); // 0x10 = executeWithValue

        // Convert ETH amount to exactly 10 bytes
        // Use uint80 which fits in 10 bytes (2^80 - 1 is much larger than any reasonable ETH amount)
        uint80 ethAmount80 = uint80(_ethAmount);
        bytes memory ethBytes = abi.encodePacked(ethAmount80);

        // Construct calldata:
        // [0x00][secondByte][signature][nonce][outputContract][ethAmount][arguments]
        bytes memory fallbackCalldata = abi.encodePacked(
            bytes1(0x00), // Prefix
            secondByte, // Function selector + nonce length
            _signature, // 65 bytes signature
            nonceBytes, // Nonce data
            _outputContract, // 20 bytes output contract
            ethBytes, // ETH amount
            _arguments // Function arguments
        );

        return fallbackCalldata;
    }
}
