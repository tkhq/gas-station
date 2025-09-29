// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {TKGasDelegate} from "../src/TKGasStation/TKGasDelegate.sol";
import {IBatchExecution} from "../src/TKGasStation/interfaces/IBatchExecution.sol";
import "../test/Mocks/MockERC20.sol";

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
        assertEq(TKGasDelegate(user).timeboxedCounter(), 0);
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

        // Measure gas usa= gasleft();

        bool success;
        bytes memory result;
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        (success, result) = TKGasDelegate(user).execute(
            nonce,
            address(mockToken),
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18),
            signature
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
            nonce,
            address(mockToken),
            abi.encodeWithSelector(mockToken.returnPlusHoldings.selector, 10 * 10 ** 18),
            signature
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
        (success, result) = TKGasDelegate(user).execute(nonce, receiver, 1 ether, "", signature);

        assertEq(success, true);
        assertEq(result.length, 0); // returns 0x00

        vm.stopPrank();

        assertEq(address(receiver).balance, 1 ether);
        assertEq(TKGasDelegate(user).nonce(), nonce + 1);

        // Note: In tests, the test contract pays gas, not the pranked address
        // The paymaster is just the msg.sender, but gas comes from the test contract
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
            nonce + 1,
            address(mockToken),
            abi.encodeWithSelector(mockToken.returnPlusHoldings.selector, 10 * 10 ** 18),
            signature
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
            nonce,
            address(mockToken),
            abi.encodeWithSelector(mockToken.returnPlusHoldings.selector, 10 * 10 ** 18),
            signature
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
            nonce,
            address(mockToken),
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18),
            signature
        );
        vm.stopPrank();

        assertEq(success, true);
        assertEq(TKGasDelegate(user).nonce(), nonce + 1);

        // Second execution with same nonce should revert
        vm.prank(paymaster);
        vm.expectRevert();
        (success, result) = TKGasDelegate(user).execute(
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

        uint128 nonce = TKGasDelegate(user).nonce();

        // Create batch execution with multiple transfers
        IBatchExecution.Execution[] memory executions = new IBatchExecution.Execution[](2);
        executions[0] = IBatchExecution.Execution({
            outputContract: address(mockToken),
            ethAmount: 0,
            arguments: abi.encodeWithSelector(mockToken.transfer.selector, receiver1, 10 * 10 ** 18)
        });
        executions[1] = IBatchExecution.Execution({
            outputContract: address(mockToken),
            ethAmount: 0,
            arguments: abi.encodeWithSelector(mockToken.transfer.selector, receiver2, 15 * 10 ** 18)
        });

        // Create signature for batch execution
        bytes memory signature = _signBatch(USER_PRIVATE_KEY, user, nonce, executions);

        bool success;
        bytes[] memory results;

        vm.prank(paymaster);
        (success, results) = TKGasDelegate(user).executeBatch(nonce, executions, signature);
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
        IBatchExecution.Execution[] memory executions = new IBatchExecution.Execution[](2);
        executions[0] = IBatchExecution.Execution({
            outputContract: address(mockToken),
            ethAmount: 0,
            arguments: abi.encodeWithSelector(mockToken.transfer.selector, receiver1, 10 * 10 ** 18)
        });
        executions[1] = IBatchExecution.Execution({
            outputContract: address(mockToken),
            ethAmount: 0,
            arguments: abi.encodeWithSelector(mockToken.transfer.selector, receiver2, 15 * 10 ** 18)
        });

        // Create signature for batch execution
        bytes memory signature = _signBatch(USER_PRIVATE_KEY, user, nonce, executions);

        IBatchExecution.Execution[] memory badExecutions = new IBatchExecution.Execution[](2);
        badExecutions[0] = IBatchExecution.Execution({
            outputContract: address(mockToken),
            ethAmount: 0,
            arguments: abi.encodeWithSelector(mockToken.transfer.selector, receiver1, 20 * 10 ** 18)
        });
        badExecutions[1] = IBatchExecution.Execution({
            outputContract: address(mockToken),
            ethAmount: 0,
            arguments: abi.encodeWithSelector(mockToken.transfer.selector, receiver2, 15 * 10 ** 18)
        });

        bool success;
        bytes[] memory results;

        vm.prank(paymaster);
        vm.expectRevert();
        (success, results) = TKGasDelegate(user).executeBatch(nonce, badExecutions, signature);
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
        IBatchExecution.Execution[] memory _executions
    ) internal returns (bytes memory) {
        address signer = vm.addr(_privateKey);
        vm.startPrank(signer);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(_privateKey, TKGasDelegate(_publicKey).hashBatchExecution(_nonce, _executions));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();
        return signature;
    }

    function testGassyExecuteBatchSizeLimit() public {
        mockToken.mint(user, 1000 * 10 ** 18);
        address receiver = makeAddr("receiver");

        uint128 nonce = TKGasDelegate(user).nonce();

        // Create batch execution with 51 transactions (exceeds MAX_BATCH_SIZE of 50)
        IBatchExecution.Execution[] memory executions = new IBatchExecution.Execution[](51);
        for (uint256 i = 0; i < 51; i++) {
            executions[i] = IBatchExecution.Execution({
                outputContract: address(mockToken),
                ethAmount: 0,
                arguments: abi.encodeWithSelector(mockToken.transfer.selector, receiver, 1 * 10 ** 18)
            });
        }

        // Create signature for batch execution
        bytes memory signature = _signBatch(USER_PRIVATE_KEY, user, nonce, executions);

        // Should revert due to batch size limit
        vm.prank(paymaster);
        vm.expectRevert();
        TKGasDelegate(user).executeBatch(nonce, executions, signature);
        vm.stopPrank();
    }

    function testGassyExecuteBatchMaxSizeAllowed() public {
        mockToken.mint(user, 1000 * 10 ** 18);
        address receiver = makeAddr("receiver");

        uint128 nonce = TKGasDelegate(user).nonce();

        // Create batch execution with exactly 50 transactions (MAX_BATCH_SIZE)
        IBatchExecution.Execution[] memory executions = new IBatchExecution.Execution[](50);
        for (uint256 i = 0; i < 50; i++) {
            executions[i] = IBatchExecution.Execution({
                outputContract: address(mockToken),
                ethAmount: 0,
                arguments: abi.encodeWithSelector(mockToken.transfer.selector, receiver, 1 * 10 ** 18)
            });
        }

        // Create signature for batch execution
        bytes memory signature = _signBatch(USER_PRIVATE_KEY, user, nonce, executions);

        bool success;
        bytes[] memory results;

        // Should succeed with exactly MAX_BATCH_SIZE transactions
        vm.prank(paymaster);
        (success, results) = TKGasDelegate(user).executeBatch(nonce, executions, signature);
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
        TKGasDelegate(user).burnNonce(nonce, signature);
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
        TKGasDelegate(user).burnNonce(nonce + 1, signature);
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
        TKGasDelegate(user).burnNonce(nonce, burnSignature);
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
        TKGasDelegate(user).burnNonce(newNonce, signature);
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

    function _signTimeboxed(
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
            _privateKey, TKGasDelegate(_publicKey).hashTimeboxedExecution(_counter, _deadline, _sender, _outputContract)
        );
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();
        return signature;
    }

    function _signTimeboxedArbitrary(
        uint256 _privateKey,
        address payable _publicKey,
        uint128 _counter,
        uint128 _deadline,
        address _sender
    ) internal returns (bytes memory) {
        address signer = vm.addr(_privateKey);
        vm.startPrank(signer);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            _privateKey, TKGasDelegate(_publicKey).hashArbitraryTimeboxedExecution(_counter, _deadline, _sender)
        );
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();
        return signature;
    }

    function _signBurnTimeboxedCounter(
        uint256 _privateKey,
        address payable _publicKey,
        uint128 _counter,
        address _sender
    ) internal returns (bytes memory) {
        address signer = vm.addr(_privateKey);
        vm.startPrank(signer);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(_privateKey, TKGasDelegate(_publicKey).hashBurnTimeboxedCounter(_counter, _sender));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();
        return signature;
    }

    // ============ TIMEBOXED EXECUTION TESTS ============

    function testExecuteTimeboxed() public {
        uint128 counter = TKGasDelegate(user).timeboxedCounter();
        uint128 deadline = uint128(block.timestamp + 1 hours);
        uint256 ethAmount = 0.1 ether;
        address reciever = makeAddr("reciever");
        bytes memory executionData = ""; //abi.encodeWithSignature("");

        // Fund the user contract
        vm.deal(user, 1 ether);

        // Sign the timeboxed execution
        bytes memory signature = _signTimeboxed(USER_PRIVATE_KEY, user, counter, deadline, paymaster, reciever);

        // Execute timeboxed transaction
        vm.startPrank(paymaster);
        (bool success,) =
            TKGasDelegate(user).executeTimeboxed(counter, deadline, reciever, ethAmount, executionData, signature);
        vm.stopPrank();

        assertTrue(success);
        assertEq(TKGasDelegate(user).timeboxedCounter(), 0); // Counter should NOT increment
        assertEq(reciever.balance, ethAmount);
        assertEq(user.balance, 1 ether - ethAmount);
    }

    function testExecuteTimeboxedArbitrary() public {
        uint128 counter = TKGasDelegate(user).timeboxedCounter();
        uint128 deadline = uint128(block.timestamp + 1 hours);
        uint256 ethAmount = 0.1 ether;
        address reciever = makeAddr("reciever");
        bytes memory executionData = ""; //abi.encodeWithSignature("");

        // Fund the user contract
        vm.deal(user, 1 ether);

        // Sign the timeboxed execution
        bytes memory signature = _signTimeboxedArbitrary(USER_PRIVATE_KEY, user, counter, deadline, paymaster);

        // Execute timeboxed transaction
        vm.startPrank(paymaster);
        (bool success,) = TKGasDelegate(user).executeTimeboxedArbitrary(
            counter, deadline, reciever, ethAmount, executionData, signature
        );
        vm.stopPrank();

        assertTrue(success);
        assertEq(TKGasDelegate(user).timeboxedCounter(), 0); // Counter should NOT increment
        assertEq(reciever.balance, ethAmount);
        assertEq(user.balance, 1 ether - ethAmount);
    }

    function testExecuteTimeboxedArbitraryRevertsDeadlineExceeded() public {
        uint128 counter = TKGasDelegate(user).timeboxedCounter();
        uint128 deadline = uint128(block.timestamp + 1 hours);
        uint256 ethAmount = 0.1 ether;
        address reciever = makeAddr("reciever");
        bytes memory executionData = ""; //abi.encodeWithSignature("");

        // Fund the user contract
        vm.deal(user, 1 ether);

        // Sign the timeboxed execution
        bytes memory signature = _signTimeboxedArbitrary(USER_PRIVATE_KEY, user, counter, deadline, paymaster);

        // Execute timeboxed transaction
        vm.startPrank(paymaster);
        vm.expectRevert(); //invalid signature
        TKGasDelegate(user).executeTimeboxedArbitrary(
            counter,
            deadline + 1, // makes the signature unable to be validated
            reciever,
            ethAmount,
            executionData,
            signature
        );
        vm.warp(deadline + 1);
        vm.expectRevert(TKGasDelegate.DeadlineExceeded.selector); //deadline exceeded
        TKGasDelegate(user).executeTimeboxedArbitrary(counter, deadline, reciever, ethAmount, executionData, signature);
        vm.stopPrank();
    }

    function testExecuteBatchTimeboxedArbitrary() public {
        uint128 counter = TKGasDelegate(user).timeboxedCounter();
        uint128 deadline = uint128(block.timestamp + 1 hours);

        // Fund the user contract
        vm.deal(user, 1 ether);

        // Create batch executions
        IBatchExecution.Execution[] memory executions = new IBatchExecution.Execution[](2);
        address receiver1 = makeAddr("receiver1");
        address receiver2 = makeAddr("receiver2");

        executions[0] = IBatchExecution.Execution({outputContract: receiver1, ethAmount: 0.05 ether, arguments: ""});
        executions[1] = IBatchExecution.Execution({outputContract: receiver2, ethAmount: 0.05 ether, arguments: ""});

        // Sign the arbitrary timeboxed execution
        bytes memory signature = _signTimeboxedArbitrary(USER_PRIVATE_KEY, user, counter, deadline, paymaster);

        // Execute batch timeboxed transaction
        vm.startPrank(paymaster);
        (bool success, bytes[] memory results) =
            TKGasDelegate(user).executeBatchTimeboxedArbitrary(counter, deadline, executions, signature);
        vm.stopPrank();

        assertTrue(success);
        assertEq(results.length, 2);
        assertEq(TKGasDelegate(user).timeboxedCounter(), 0); // Counter should NOT increment
        assertEq(receiver1.balance, 0.05 ether);
        assertEq(receiver2.balance, 0.05 ether);
        assertEq(user.balance, 1 ether - 0.1 ether);
    }

    function testExecuteBatchTimeboxed() public {
        uint128 counter = TKGasDelegate(user).timeboxedCounter();
        uint128 deadline = uint128(block.timestamp + 1 hours);

        // Fund the user contract
        vm.deal(user, 1 ether);

        // Create batch executions with same output contract
        IBatchExecution.Execution[] memory executions = new IBatchExecution.Execution[](3);
        address receiver = makeAddr("receiver");

        executions[0] = IBatchExecution.Execution({outputContract: receiver, ethAmount: 0.1 ether, arguments: ""});
        executions[1] = IBatchExecution.Execution({outputContract: receiver, ethAmount: 0.2 ether, arguments: ""});
        executions[2] = IBatchExecution.Execution({outputContract: receiver, ethAmount: 0.3 ether, arguments: ""});

        // Sign the timeboxed execution
        bytes memory signature = _signTimeboxed(USER_PRIVATE_KEY, user, counter, deadline, paymaster, receiver);

        // Execute batch timeboxed transaction
        vm.startPrank(paymaster);
        (bool success, bytes[] memory results) =
            TKGasDelegate(user).executeBatchTimeboxed(counter, deadline, receiver, executions, signature);
        vm.stopPrank();

        assertTrue(success);
        assertEq(results.length, 3);
        assertEq(TKGasDelegate(user).timeboxedCounter(), 0); // Counter should NOT increment
        assertEq(receiver.balance, 0.6 ether); // 0.1 + 0.2 + 0.3
        assertEq(user.balance, 1 ether - 0.6 ether);
    }

    function testBurnTimeboxedCounter() public {
        uint128 counter = 0;

        // Sign the burn timeboxed counter
        bytes memory signature = _signBurnTimeboxedCounter(USER_PRIVATE_KEY, user, counter, paymaster);

        // Burn timeboxed counter
        vm.startPrank(paymaster);
        TKGasDelegate(user).burnTimeboxedCounter(counter, paymaster, signature);
        vm.stopPrank();

        assertEq(TKGasDelegate(user).timeboxedCounter(), 1); // Counter should increment
    }

    function testDirectBurnTimeboxedCounter() public {
        vm.startPrank(user, user);
        TKGasDelegate(user).burnTimeboxedCounter();
        vm.stopPrank();

        assertEq(TKGasDelegate(user).timeboxedCounter(), 1); // Counter should increment

        // Burn timeboxed counter again
        vm.startPrank(user, user);
        TKGasDelegate(user).burnTimeboxedCounter();
        vm.stopPrank();

        assertEq(TKGasDelegate(user).timeboxedCounter(), 2); // Counter should increment again
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
            nonce,
            address(mockToken),
            abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18),
            signature
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
        (success, result) = TKGasDelegate(user).execute(nonce, receiver, transferAmount, "", signature);
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
            nonce, address(mockToken), abi.encodeWithSelector(mockToken.returnPlusHoldings.selector, 100), signature
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
}
