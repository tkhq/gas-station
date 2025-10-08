// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test, console} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {TKGasStation} from "../src/TKGasStation/TKGasStation.sol";
import {MockDelegate} from "./mocks/MockDelegate.t.sol";
import {MockERC20} from "./mocks/MockERC20.t.sol";
import {IBatchExecution} from "../src/TKGasStation/interfaces/IBatchExecution.sol";

contract TKGasStationTest is Test {
    TKGasStation public tkGasStation;
    MockDelegate public tkGasDelegate;
    MockERC20 public mockToken;

    address public user;
    address public paymaster;

    uint256 constant USER_PRIVATE_KEY = 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA;

    function setUp() public {
        tkGasDelegate = new MockDelegate();
        tkGasStation = new TKGasStation(address(tkGasDelegate));
        user = vm.addr(USER_PRIVATE_KEY);
        paymaster = makeAddr("paymaster");

        mockToken = new MockERC20("TestToken", "TT");

        vm.deal(paymaster, 10 ether);
        vm.deal(user, 5 ether);

        _delegate(USER_PRIVATE_KEY, address(tkGasDelegate));
    }

    function _delegate(uint256 _privateKey, address _target) internal {
        vm.startPrank(vm.addr(_privateKey));
        VmSafe.SignedDelegation memory signedDelegation = vm.signDelegation(_target, _privateKey);
        vm.stopPrank();

        vm.prank(paymaster);
        vm.attachDelegation(signedDelegation);
    }

    function _sign(
        uint256 _privateKey,
        address _publicKey,
        uint128 _nonce,
        uint32 _deadline,
        address _to,
        uint256 _value,
        bytes memory _args
    ) internal returns (bytes memory) {
        vm.startPrank(_publicKey);
        bytes32 hash = MockDelegate(payable(_publicKey)).hashExecution(_nonce, _deadline, _to, _value, _args);
        vm.stopPrank();

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_privateKey, hash);
        return abi.encodePacked(r, s, v);
    }

    function _buildExecuteWithValueData(
        bytes memory _signature,
        uint128 _nonce,
        uint32 _deadline,
        address _to,
        uint256 _value,
        bytes memory _args
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(_signature, bytes16(_nonce), bytes4(_deadline), _to, _value, _args);
    }

    function testInit() public view {
        assertTrue(tkGasStation.tkGasDelegate() == address(tkGasDelegate));
    }

    function testERC20Transfer() public {
        console.log("=== TKGasStation ERC20 TRANSFER TEST ===");

        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        // Get current nonce
        MockDelegate(payable(address(tkGasDelegate))).spoof_Nonce(1);
        uint128 nonce = MockDelegate(payable(user)).nonce();

        // Create signature
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        bytes memory signature =
            _sign(USER_PRIVATE_KEY, user, nonce, uint32(block.timestamp + 86400), address(mockToken), 0, args);

        // Build data for parameterized execute (signature + nonce + args)
        bytes memory paramData =
            abi.encodePacked(signature, bytes16(nonce), bytes4(uint32(block.timestamp + 86400)), args);

        uint256 gasBefore = gasleft();
        bytes memory result = tkGasStation.execute(user, address(mockToken), 0, paramData);
        uint256 gasAfter = gasleft();
        uint256 gasUsed = gasBefore - gasAfter;
        assertEq(mockToken.balanceOf(receiver), 10 * 10 ** 18);
        assertTrue(abi.decode(result, (bool)));

        console.log("TKGasStation ERC20 transfer gas: %s", gasUsed);
    }

    function testERC20TransferNoReturn() public {
        console.log("=== TKGasStation ERC20 NO RETURN TRANSFER TEST ===");

        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        // Get current nonce
        MockDelegate(payable(address(tkGasDelegate))).spoof_Nonce(1);
        uint128 nonce = MockDelegate(payable(user)).nonce();

        // Create signature
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);
        bytes memory signature =
            _sign(USER_PRIVATE_KEY, user, nonce, uint32(block.timestamp + 86400), address(mockToken), 0, args);

        // Build data for parameterized execute (signature + nonce + args)
        bytes memory paramData =
            abi.encodePacked(signature, bytes16(nonce), bytes4(uint32(block.timestamp + 86400)), args);

        // Execute ERC20 transfer through TKGasStation (parameterized API, no return)
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        tkGasStation.executeNoReturn(user, address(mockToken), 0, paramData);
        uint256 gasAfter = gasleft();
        uint256 gasUsed = gasBefore - gasAfter;
        assertEq(mockToken.balanceOf(receiver), 10 * 10 ** 18);

        console.log("TKGasStation ERC20 no return transfer gas: %s", gasUsed);
    }

    function testETHTransfer() public {
        address payable receiver = payable(makeAddr("receiver"));
        uint256 transferAmount = 1 ether;

        // Fund the user with ETH
        vm.deal(user, 2 ether);

        // Get current nonce
        MockDelegate(payable(address(tkGasDelegate))).spoof_Nonce(1);
        uint128 nonce = MockDelegate(payable(user)).nonce();

        // Create signature
        uint32 deadline = uint32(block.timestamp + 86400);
        bytes memory signature =
            _sign(USER_PRIVATE_KEY, user, nonce, uint32(block.timestamp + 86400), receiver, transferAmount, "");

        // Execute ETH transfer through TKGasStation (parameterized API with value)
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        bytes memory paramData = abi.encodePacked(signature, bytes16(nonce), bytes4(deadline), "");
        bytes memory result = tkGasStation.execute(user, receiver, transferAmount, paramData);

        uint256 gasAfter = gasleft();
        uint256 gasUsed = gasBefore - gasAfter;
        assertEq(result.length, 0); // ETH transfers return empty result
        assertEq(address(receiver).balance, transferAmount);

        console.log("TKGasStation ETH transfer gas: %s", gasUsed);
    }

    function testGasComparisonTable() public {
        console.log("=== COMPREHENSIVE GAS COMPARISON TABLE ===");

        mockToken.mint(user, 30 * 10 ** 18);
        address receiver1 = makeAddr("receiver_1");
        address receiver2 = makeAddr("receiver_2");

        // Test 1: execute (parameterized, with return)
        MockDelegate(payable(address(tkGasDelegate))).spoof_Nonce(1);
        uint128 nonce1 = MockDelegate(payable(user)).nonce();
        bytes memory args1 = abi.encodeWithSelector(mockToken.transfer.selector, receiver1, 10 * 10 ** 18);
        bytes memory signature1 =
            _sign(USER_PRIVATE_KEY, user, nonce1, uint32(block.timestamp + 86400), address(mockToken), 0, args1);
        bytes memory paramData1 =
            abi.encodePacked(signature1, bytes16(nonce1), bytes4(uint32(block.timestamp + 86400)), args1);

        vm.prank(paymaster);
        uint256 gasBefore1 = gasleft();
        bytes memory result1 = tkGasStation.execute(user, address(mockToken), 0, paramData1);
        uint256 gasUsed1 = gasBefore1 - gasleft();

        // Test 2: executeNoReturn (parameterized, no return)
        MockDelegate(payable(address(tkGasDelegate))).spoof_Nonce(1);
        uint128 nonce2 = MockDelegate(payable(user)).nonce();
        bytes memory args2 = abi.encodeWithSelector(mockToken.transfer.selector, receiver2, 10 * 10 ** 18);
        bytes memory signature2 =
            _sign(USER_PRIVATE_KEY, user, nonce2, uint32(block.timestamp + 86400), address(mockToken), 0, args2);
        bytes memory paramData2 =
            abi.encodePacked(signature2, bytes16(nonce2), bytes4(uint32(block.timestamp + 86400)), args2);

        vm.prank(paymaster);
        uint256 gasBefore2 = gasleft();
        tkGasStation.executeNoReturn(user, address(mockToken), 0, paramData2);
        uint256 gasUsed2 = gasBefore2 - gasleft();

        // Verify transfers worked
        assertEq(mockToken.balanceOf(receiver1), 10 * 10 ** 18);
        assertEq(mockToken.balanceOf(receiver2), 10 * 10 ** 18);

        // Log results
        console.log("");
        console.log("+---------------------------------------------------+");
        console.log("| Function Type           | Gas Used | vs Base      |");
        console.log("+---------------------------------------------------+");
        console.log("| execute(param)          | %s |   base      |", gasUsed1);
        console.log(
            "| executeNoReturn(param)  | %s | %s |",
            gasUsed2,
            gasUsed2 > gasUsed1 ? gasUsed2 - gasUsed1 : gasUsed1 - gasUsed2
        );
        console.log("+---------------------------------------------------+");
        console.log("");

        if (gasUsed1 < gasUsed2) {
            console.log(
                "execute is %s gas more efficient (%s%% savings)",
                gasUsed2 - gasUsed1,
                ((gasUsed2 - gasUsed1) * 100) / gasUsed2
            );
        } else {
            console.log(
                "executeNoReturn is %s gas more efficient (%s%% savings)",
                gasUsed1 - gasUsed2,
                ((gasUsed1 - gasUsed2) * 100) / gasUsed1
            );
        }
    }

    function testNotDelegatedRevert() public {
        // Create a new user that is NOT delegated
        uint256 newUserPrivateKey = 0xBBBBBB;
        address payable newUser = payable(vm.addr(newUserPrivateKey));

        mockToken.mint(newUser, 10 * 10 ** 18);
        address receiver = makeAddr("receiver");

        MockDelegate(payable(address(tkGasDelegate))).spoof_Nonce(1);
        uint128 nonce = 1; // Use a fixed nonce since we can't get state from non-delegated user
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 5 * 10 ** 18);

        // Create signature manually since newUser is not delegated
        bytes32 hash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                keccak256(
                    abi.encode(
                        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                        keccak256(bytes("TKGasDelegate")),
                        keccak256(bytes("1")),
                        block.chainid,
                        newUser
                    )
                ),
                keccak256(
                    abi.encode(
                        keccak256("Execution(uint128 nonce,address to,uint256 value,bytes data)"),
                        nonce,
                        address(mockToken),
                        0,
                        keccak256(args)
                    )
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(newUserPrivateKey, hash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory paramData =
            abi.encodePacked(signature, bytes16(nonce), bytes4(uint32(block.timestamp + 86400)), args);

        vm.expectRevert();
        tkGasStation.execute(newUser, address(mockToken), 0, paramData);
    }

    function testIsDelegated() public {
        assertTrue(tkGasStation.isDelegated(user));

        address newUser = makeAddr("newUser");
        assertFalse(tkGasStation.isDelegated(newUser));
    }

    function testGetNonce() public {
        uint128 nonce = tkGasStation.getNonce(user);
        assertEq(nonce, 0); // Should start at 0
    }

    function testBurnNonce() public {
        MockDelegate(payable(address(tkGasDelegate))).spoof_Nonce(1);
        uint128 nonce = MockDelegate(payable(user)).nonce();

        // Create a proper signature for burnNonce
        vm.startPrank(user);
        bytes32 hash = MockDelegate(payable(user)).hashBurnNonce(nonce);
        vm.stopPrank();

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_PRIVATE_KEY, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Burn nonce should work
        tkGasStation.burnNonce(user, signature, nonce);

        // Nonce should be incremented
        uint128 newNonce = tkGasStation.getNonce(user);
        assertEq(newNonce, nonce + 1);
    }

    function testReceiveReverts() public {
        vm.expectRevert();
        address(tkGasStation).call{value: 1 ether}("");
    }

    function testFallbackInvalidFunctionSelectorRevert() public {
        // Test fallback with invalid function selector
        vm.expectRevert();
        address(tkGasStation).call(abi.encodePacked(bytes1(0x00), user, bytes1(0x80))); // Invalid selector
    }

    // Tests for newly implemented no-return functions
    function testApproveThenExecuteNoReturn() public {
        console.log("=== TESTING approveThenExecuteNoReturn ===");

        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        // Spoof nonce
        MockDelegate(payable(address(tkGasDelegate))).spoof_Nonce(3);
        uint128 nonce = MockDelegate(payable(user)).nonce();

        // Create signature for approveThenExecute
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);

        vm.startPrank(user);
        bytes32 hash = MockDelegate(payable(user)).hashApproveThenExecute(
            nonce,
            uint32(block.timestamp + 86400), // deadline
            address(mockToken), // erc20
            address(mockToken), // spender
            10 * 10 ** 18, // approveAmount
            address(mockToken), // outputContract
            0, // ethAmount
            args
        );
        vm.stopPrank();

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_PRIVATE_KEY, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Build data for approveThenExecuteNoReturn (use simple format like execute)
        bytes memory paramData =
            abi.encodePacked(signature, bytes16(nonce), bytes4(uint32(block.timestamp + 86400)), args);

        // Execute through TKGasStation
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        tkGasStation.approveThenExecuteNoReturn(
            user, address(mockToken), 0, address(mockToken), address(mockToken), 10 * 10 ** 18, paramData
        );
        uint256 gasAfter = gasleft();
        uint256 gasUsed = gasBefore - gasAfter;

        assertEq(mockToken.balanceOf(receiver), 10 * 10 ** 18);
        console.log("approveThenExecuteNoReturn gas: %s", gasUsed);
    }

    function testExecuteBatchNoReturn() public {
        console.log("=== TESTING executeBatchNoReturn ===");

        mockToken.mint(user, 20 * 10 ** 18);
        address receiver1 = makeAddr("receiver1");
        address receiver2 = makeAddr("receiver2");

        // Spoof nonce
        MockDelegate(payable(address(tkGasDelegate))).spoof_Nonce(4);
        uint128 nonce = MockDelegate(payable(user)).nonce();

        // Create batch calls
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](2);
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, receiver1, 5 * 10 ** 18)
        });
        calls[1] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, receiver2, 5 * 10 ** 18)
        });

        // Create signature
        vm.startPrank(user);
        bytes32 hash = MockDelegate(payable(user)).hashBatchExecution(nonce, uint32(block.timestamp + 86400), calls);
        vm.stopPrank();

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_PRIVATE_KEY, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Build data for executeBatchNoReturn (use simple format like execute)
        bytes memory paramData =
            abi.encodePacked(signature, bytes16(nonce), bytes4(uint32(block.timestamp + 86400)), abi.encode(calls));

        // Execute through TKGasStation
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        tkGasStation.executeBatchNoReturn(user, calls, paramData);
        uint256 gasAfter = gasleft();
        uint256 gasUsed = gasBefore - gasAfter;

        assertEq(mockToken.balanceOf(receiver1), 5 * 10 ** 18);
        assertEq(mockToken.balanceOf(receiver2), 5 * 10 ** 18);
        console.log("executeBatchNoReturn gas: %s", gasUsed);
    }

    function testApproveThenExecute() public {
        console.log("=== TESTING approveThenExecute (with return) ===");

        mockToken.mint(user, 20 * 10 ** 18);
        address receiver = makeAddr("receiver");

        // Spoof nonce
        MockDelegate(payable(address(tkGasDelegate))).spoof_Nonce(5);
        uint128 nonce = MockDelegate(payable(user)).nonce();

        // Create signature for approveThenExecute
        bytes memory args = abi.encodeWithSelector(mockToken.transfer.selector, receiver, 10 * 10 ** 18);

        vm.startPrank(user);
        bytes32 hash = MockDelegate(payable(user)).hashApproveThenExecute(
            nonce,
            uint32(block.timestamp + 86400), // deadline
            address(mockToken), // erc20
            address(mockToken), // spender
            10 * 10 ** 18, // approveAmount
            address(mockToken), // outputContract
            0, // ethAmount
            args
        );
        vm.stopPrank();

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_PRIVATE_KEY, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Build data for approveThenExecute
        bytes memory paramData =
            abi.encodePacked(signature, bytes16(nonce), bytes4(uint32(block.timestamp + 86400)), args);

        // Execute through TKGasStation
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        bytes memory result = tkGasStation.approveThenExecute(
            user, address(mockToken), 0, address(mockToken), address(mockToken), 10 * 10 ** 18, paramData
        );
        uint256 gasAfter = gasleft();
        uint256 gasUsed = gasBefore - gasAfter;

        assertEq(mockToken.balanceOf(receiver), 10 * 10 ** 18);
        assertTrue(abi.decode(result, (bool)));
        console.log("approveThenExecute gas: %s", gasUsed);
    }

    function testExecuteBatch() public {
        console.log("=== TESTING executeBatch (with return) ===");

        mockToken.mint(user, 20 * 10 ** 18);
        address receiver1 = makeAddr("receiver1");
        address receiver2 = makeAddr("receiver2");

        // Spoof nonce
        MockDelegate(payable(address(tkGasDelegate))).spoof_Nonce(6);
        uint128 nonce = MockDelegate(payable(user)).nonce();

        // Create batch calls
        IBatchExecution.Call[] memory calls = new IBatchExecution.Call[](2);
        calls[0] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, receiver1, 5 * 10 ** 18)
        });
        calls[1] = IBatchExecution.Call({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSelector(mockToken.transfer.selector, receiver2, 5 * 10 ** 18)
        });

        // Create signature
        vm.startPrank(user);
        bytes32 hash = MockDelegate(payable(user)).hashBatchExecution(nonce, uint32(block.timestamp + 86400), calls);
        vm.stopPrank();

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_PRIVATE_KEY, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Build data for executeBatch
        bytes memory paramData =
            abi.encodePacked(signature, bytes16(nonce), bytes4(uint32(block.timestamp + 86400)), abi.encode(calls));

        // Execute through TKGasStation
        vm.prank(paymaster);
        uint256 gasBefore = gasleft();
        bytes[] memory results = tkGasStation.executeBatch(user, calls, paramData);
        uint256 gasAfter = gasleft();
        uint256 gasUsed = gasBefore - gasAfter;

        assertEq(mockToken.balanceOf(receiver1), 5 * 10 ** 18);
        assertEq(mockToken.balanceOf(receiver2), 5 * 10 ** 18);
        assertEq(results.length, 2);
        assertTrue(abi.decode(results[0], (bool)));
        assertTrue(abi.decode(results[1], (bool)));
        console.log("executeBatch gas: %s", gasUsed);
    }
}
