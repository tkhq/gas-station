// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test, console} from "forge-std/Test.sol";
import {MockContractInteraction} from "./mocks/MockContractInteraction.sol";
import {TKSmartWalletFactory} from "../src/TKSmartWalletFactory.sol";
import {TKSmartWalletManager} from "../src/TKSmartWalletManager.sol";
import {BasicTKSmartWallet} from "../src/BasicTKSmartWallet.sol";

// Import VmSafe to access the SignedDelegation struct
import {VmSafe} from "forge-std/Vm.sol";

contract TKSmartWalletTest is Test {
    MockContractInteraction public mockContract;
    TKSmartWalletFactory public factory;
    TKSmartWalletManager public manager;
    BasicTKSmartWallet public smartWallet;

    address public constant OWNER = address(0x1);
    address public constant USER2 = address(0x2);

    uint256 public constant A_PRIVATE_KEY = 0xAAAAAA;
    uint256 public constant B_PRIVATE_KEY = 0xBBBBBB;
    uint256 public constant C_PRIVATE_KEY = 0xCCCCCC;
    address payable public A_ADDRESS;  
    address payable public B_ADDRESS;  
    address payable public C_ADDRESS;
    bytes4 public constant ADD_FUNCTION = bytes4(keccak256("add(uint256)"));
    bytes4 public constant SUB_FUNCTION = bytes4(keccak256("sub(uint256)"));
    bytes4[] public emptyFunctions = new bytes4[](0);
    uint256 public constant ONE = 1;

    function setUp() public {

        mockContract = new MockContractInteraction();
        A_ADDRESS = payable(vm.addr(A_PRIVATE_KEY)); // 0x3545A2F3928d5b21E71a790FB458F4AE03306C55
        B_ADDRESS = payable(vm.addr(B_PRIVATE_KEY)); // 0xA2379A9c84396B4287d91B7D74470cc9304e3b39
        C_ADDRESS = payable(vm.addr(C_PRIVATE_KEY));
        factory = new TKSmartWalletFactory();
    }

    function test_CreateSmartWallet() public {
        (address managerAddress, address payable smartWalletAddress) = factory.createSmartWallet("TKSmartWallet", "1", OWNER, address(mockContract), emptyFunctions);
        assertEq(managerAddress != address(0), true);
        assertEq(smartWalletAddress != address(0), true);

        manager = TKSmartWalletManager(managerAddress);
        smartWallet = BasicTKSmartWallet(smartWalletAddress);
        
        assertEq(managerAddress, smartWallet.managementContract());
        assertEq(manager.allowedFunctions() == 0, true);

        vm.startBroadcast(A_PRIVATE_KEY);
        VmSafe.SignedDelegation memory signedDelegation = vm.signDelegation(address(smartWallet), A_PRIVATE_KEY);
        vm.attachDelegation(signedDelegation);

        bytes memory code = address(A_ADDRESS).code;
        assertGt(code.length, 0, "no code written to A");

        assertEq(BasicTKSmartWallet(A_ADDRESS).managementContract(), address(manager));

        vm.stopBroadcast();

    }

    function test_execute() public {

        (address managerAddress, address payable smartWalletAddress) = factory.createSmartWallet("TKSmartWallet", "1", OWNER, address(mockContract), emptyFunctions);
        manager = TKSmartWalletManager(managerAddress);
        smartWallet = BasicTKSmartWallet(smartWalletAddress);
        uint256 timeout = block.timestamp + 1000;
        // delegate 
        vm.startBroadcast(A_PRIVATE_KEY);
        vm.signAndAttachDelegation(smartWalletAddress, A_PRIVATE_KEY);
        vm.stopBroadcast();
        
        // Check if delegation created contract at A_ADDRESS
        bytes memory code = address(A_ADDRESS).code;
        assertGt(code.length, 0, "No contract deployed at A_ADDRESS via delegation");
        (bytes memory signature, ) = _sign(A_PRIVATE_KEY, manager, B_ADDRESS, timeout);


        assertEq(mockContract.getBalance(A_ADDRESS), 0);
        assertEq(mockContract.getBalance(B_ADDRESS), 0);

        vm.startBroadcast(B_PRIVATE_KEY);
        BasicTKSmartWallet(A_ADDRESS).execute(A_ADDRESS, timeout, signature, abi.encodeWithSelector(ADD_FUNCTION, ONE));
        vm.stopBroadcast();

        assertEq(mockContract.getBalance(A_ADDRESS), 1);
        assertEq(mockContract.getBalance(B_ADDRESS), 0);

    }

    function test_execute_reverts_if_not_execution_allowed() public {

        (address managerAddress, address payable smartWalletAddress) = factory.createSmartWallet("TKSmartWallet", "1", OWNER, address(mockContract), emptyFunctions);
        manager = TKSmartWalletManager(managerAddress);
        smartWallet = BasicTKSmartWallet(smartWalletAddress);
        uint256 timeout = block.timestamp + 1000;
        // delegate 
        vm.startBroadcast(A_PRIVATE_KEY);
        vm.signAndAttachDelegation(smartWalletAddress, A_PRIVATE_KEY);
        vm.stopBroadcast();

        (bytes memory signature, ) = _sign(A_PRIVATE_KEY, manager, B_ADDRESS, timeout);

        assertEq(manager.allowExecution(), true);

        vm.startBroadcast(OWNER);
        manager.freezeExecution();
        vm.stopBroadcast();

        assertEq(manager.allowExecution(), false);

        vm.startBroadcast(B_PRIVATE_KEY);
        vm.expectRevert(abi.encodeWithSelector(TKSmartWalletManager.ExecutionNotAllowed.selector));
        BasicTKSmartWallet(A_ADDRESS).execute(A_ADDRESS, timeout, signature, abi.encodeWithSelector(ADD_FUNCTION, ONE));
        vm.stopBroadcast();

        vm.startBroadcast(OWNER);
        manager.unfreezeExecution();
        vm.stopBroadcast();

        assertEq(manager.allowExecution(), true);

        assertEq(mockContract.getBalance(A_ADDRESS), 0);
        assertEq(mockContract.getBalance(B_ADDRESS), 0);

        vm.startBroadcast(B_PRIVATE_KEY);
        BasicTKSmartWallet(A_ADDRESS).execute(A_ADDRESS, timeout, signature, abi.encodeWithSelector(ADD_FUNCTION, ONE));
        vm.stopBroadcast();

        assertEq(mockContract.getBalance(A_ADDRESS), 1);
        assertEq(mockContract.getBalance(B_ADDRESS), 0);

    }

    function test_execute_reverts_if_timeout() public {

        (address managerAddress, address payable smartWalletAddress) = factory.createSmartWallet("TKSmartWallet", "1", OWNER, address(mockContract), emptyFunctions);
        manager = TKSmartWalletManager(managerAddress);
        smartWallet = BasicTKSmartWallet(smartWalletAddress);
        uint256 timeout = block.timestamp + 1000;
        // delegate 
        vm.startBroadcast(A_PRIVATE_KEY);
        vm.signAndAttachDelegation(smartWalletAddress, A_PRIVATE_KEY);
        vm.stopBroadcast();

        (bytes memory signature, ) = _sign(A_PRIVATE_KEY, manager, B_ADDRESS, timeout);

        vm.warp(timeout + 1);
        vm.startBroadcast(B_PRIVATE_KEY);
        vm.expectRevert(abi.encodeWithSelector(TKSmartWalletManager.Timeout.selector));
        BasicTKSmartWallet(A_ADDRESS).execute(A_ADDRESS, timeout, signature, abi.encode(ADD_FUNCTION, 1));
        vm.stopBroadcast();
    }

    function test_execute_reverts_if_banned() public {

        (address managerAddress, address payable smartWalletAddress) = factory.createSmartWallet("TKSmartWallet", "1", OWNER, address(mockContract), emptyFunctions);
        manager = TKSmartWalletManager(managerAddress);
        smartWallet = BasicTKSmartWallet(smartWalletAddress);
        uint256 timeout = block.timestamp + 1000;
        // delegate 
        vm.startBroadcast(A_PRIVATE_KEY);
        vm.signAndAttachDelegation(smartWalletAddress, A_PRIVATE_KEY);
        vm.stopBroadcast();

        (bytes memory signature, ) = _sign(A_PRIVATE_KEY, manager, B_ADDRESS, timeout);

        vm.startBroadcast(OWNER);
        manager.banExecutor(B_ADDRESS);
        vm.stopBroadcast();

        vm.startBroadcast(B_PRIVATE_KEY);
        vm.expectRevert(abi.encodeWithSelector(TKSmartWalletManager.ExecutorBanned.selector));
        BasicTKSmartWallet(A_ADDRESS).execute(A_ADDRESS, timeout, signature, abi.encodeWithSelector(ADD_FUNCTION, ONE));
        vm.stopBroadcast();

        vm.startBroadcast(OWNER);
        manager.unbanExecutor(B_ADDRESS);
        vm.stopBroadcast();

        assertEq(mockContract.getBalance(A_ADDRESS), 0);
        assertEq(mockContract.getBalance(B_ADDRESS), 0);

        vm.startBroadcast(B_PRIVATE_KEY);
        BasicTKSmartWallet(A_ADDRESS).execute(A_ADDRESS, timeout, signature, abi.encodeWithSelector(ADD_FUNCTION, ONE));
        vm.stopBroadcast();

        assertEq(mockContract.getBalance(A_ADDRESS), 1);
        assertEq(mockContract.getBalance(B_ADDRESS), 0);

    }

    function test_execute_reverts_if_not_signer() public {

        (address managerAddress, address payable smartWalletAddress) = factory.createSmartWallet("TKSmartWallet", "1", OWNER, address(mockContract), emptyFunctions);
        manager = TKSmartWalletManager(managerAddress);
        smartWallet = BasicTKSmartWallet(smartWalletAddress);
        uint256 timeout = block.timestamp + 1000;
        // delegate 
        vm.startBroadcast(A_PRIVATE_KEY);
        vm.signAndAttachDelegation(smartWalletAddress, A_PRIVATE_KEY);
        vm.stopBroadcast();

        (bytes memory signature, ) = _sign(C_PRIVATE_KEY, manager, B_ADDRESS, timeout);

        vm.startBroadcast(B_PRIVATE_KEY);
        vm.expectRevert();
        BasicTKSmartWallet(A_ADDRESS).execute(A_ADDRESS, timeout, signature, abi.encodeWithSelector(ADD_FUNCTION, ONE));
        vm.stopBroadcast();

    }

    function test_execute_reverts_if_not_allowed_function() public {

        uint256 timeout = block.timestamp + 1000;
        bytes4[] memory allowedFunctions = new bytes4[](1);
        allowedFunctions[0] = ADD_FUNCTION;
        (address managerAddress, address payable smartWalletAddress) = factory.createSmartWallet("TKSmartWallet", "1", OWNER, address(mockContract), allowedFunctions);
        manager = TKSmartWalletManager(managerAddress);
        smartWallet = BasicTKSmartWallet(smartWalletAddress);

        assertEq(manager.allowedFunctions() != 0, true);
        assertEq(manager.isAllowedFunction(ADD_FUNCTION), true);
        assertEq(manager.isAllowedFunction(SUB_FUNCTION), false);

        vm.startBroadcast(A_PRIVATE_KEY);
        vm.signAndAttachDelegation(smartWalletAddress, A_PRIVATE_KEY);
        vm.stopBroadcast();


        (bytes memory signature, ) = _sign(A_PRIVATE_KEY, manager, B_ADDRESS, timeout);

        vm.startBroadcast(B_PRIVATE_KEY);
        BasicTKSmartWallet(A_ADDRESS).execute(A_ADDRESS, timeout, signature, abi.encodeWithSelector(ADD_FUNCTION, ONE));
        vm.stopBroadcast();

        assertEq(mockContract.getBalance(A_ADDRESS), 1);
        console.log("sub function");
        console.logBytes(abi.encodePacked(SUB_FUNCTION, ONE));
        console.logBytes32(manager.allowedFunctions());
        console.log(manager.isAllowedFunction(SUB_FUNCTION));
        assertEq(manager.isAllowedFunction(SUB_FUNCTION), false);
        

        vm.startBroadcast(B_PRIVATE_KEY);
        vm.expectRevert(abi.encodeWithSelector(TKSmartWalletManager.FunctionNotAllowed.selector, SUB_FUNCTION));
        BasicTKSmartWallet(A_ADDRESS).execute(A_ADDRESS, timeout, signature, abi.encodeWithSelector(SUB_FUNCTION, ONE));
        vm.stopBroadcast();
        
        assertEq(mockContract.getBalance(A_ADDRESS), 1);

    }

    function _sign(uint256 _privateKey, TKSmartWalletManager _manager, address _executor, uint256 _timeout)
        internal
        view 
        returns (bytes memory signature, bytes32 hash)
    {
        hash = _manager.getHash(_executor, _timeout);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_privateKey, hash);
        signature = abi.encodePacked(r, s, v);
    }

    function test_execute_with_eth() public {
        (address managerAddress, address payable smartWalletAddress) = factory.createSmartWallet("TKSmartWallet", "1", OWNER, address(mockContract), emptyFunctions);
        manager = TKSmartWalletManager(managerAddress);
        smartWallet = BasicTKSmartWallet(smartWalletAddress);
        uint256 timeout = block.timestamp + 1000;
        
        // delegate 
        vm.startBroadcast(A_PRIVATE_KEY);
        vm.signAndAttachDelegation(smartWalletAddress, A_PRIVATE_KEY);
        vm.stopBroadcast();
        
        // Check if delegation created contract at A_ADDRESS
        bytes memory code = address(A_ADDRESS).code;
        assertGt(code.length, 0, "No contract deployed at A_ADDRESS via delegation");
        
        (bytes memory signature, ) = _sign(A_PRIVATE_KEY, manager, B_ADDRESS, timeout);

        // Fund the executor with ETH to send with the transaction
        vm.deal(B_ADDRESS, 1 ether);
        
        assertEq(mockContract.getBalance(A_ADDRESS), 0);
        assertEq(mockContract.getETHBalance(), 0);

        // Execute with ETH value (ETH comes from B_ADDRESS, not A_ADDRESS)
        vm.startBroadcast(B_PRIVATE_KEY);
        BasicTKSmartWallet(A_ADDRESS).execute{value: 0.5 ether}(
            A_ADDRESS, 
            timeout, 
            signature, 
            abi.encodeWithSelector(mockContract.addWithETH.selector, ONE)
        );
        vm.stopBroadcast();

        // Verify the operation worked
        assertEq(mockContract.getBalance(A_ADDRESS), 1);
        assertEq(mockContract.getETHBalance(), 0.5 ether);
        
        // Verify the executor still has the remaining ETH
        assertEq(B_ADDRESS.balance, 0.5 ether);
    }

} 