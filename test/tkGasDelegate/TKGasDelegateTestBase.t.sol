// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {TKGasDelegate} from "../../src/TKGasStation/TKGasDelegate.sol";
import {MockDelegate} from "../mocks/MockDelegate.t.sol";
import {IBatchExecution} from "../../src/TKGasStation/interfaces/IBatchExecution.sol";
import "../../test/mocks/MockERC20.t.sol";

contract TKGasDelegateTestBase is Test {
    MockDelegate public tkGasDelegate;
    MockERC20 public mockToken;

    address public paymaster = makeAddr("paymaster");
    address public targetContract = makeAddr("targetContract");
    uint256 public constant USER_PRIVATE_KEY = 0xAAAAAA;
    uint256 public constant USER_PRIVATE_KEY_2 = 0xBBBBBB;
    address payable public user;
    address payable public user2;

    function setUp() public virtual {
        // Deploy MockDelegate
        tkGasDelegate = new MockDelegate();
        user = payable(vm.addr(USER_PRIVATE_KEY)); // 0x3545A2F3928d5b21E71a790FB458F4AE03306C55
        user2 = payable(vm.addr(USER_PRIVATE_KEY_2));

        // Deploy Mock ERC20
        mockToken = new MockERC20("Test Token", "TEST");

        vm.deal(paymaster, 10 ether);

        // Delegate MockDelegate for the user
        _delegate(USER_PRIVATE_KEY);
        _delegate(USER_PRIVATE_KEY_2);
    }

    function _delegate(uint256 _userPrivateKey) internal {
        Vm.SignedDelegation memory signedDelegation =
            vm.signDelegation(payable(address(tkGasDelegate)), _userPrivateKey);

        vm.prank(paymaster);
        vm.attachDelegation(signedDelegation);
        vm.stopPrank();
    }

    function _signExecute(
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
            _privateKey, MockDelegate(_publicKey).hashExecution(_nonce, _outputContract, _ethAmount, _arguments)
        );
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();
        return signature;
    }

    function _signBurnNonce(uint256 _privateKey, address payable _publicKey, uint128 _nonce)
        internal
        returns (bytes memory)
    {
        address signer = vm.addr(_privateKey);
        vm.startPrank(signer);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_privateKey, MockDelegate(_publicKey).hashBurnNonce(_nonce));
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
            vm.sign(_privateKey, MockDelegate(_publicKey).hashBurnSessionCounter(_counter, _sender));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();
        return signature;
    }

    function _constructExecuteBytesNoValue(bytes memory _signature, uint128 _nonce, address _to, bytes memory _args)
        internal
        pure
        returns (bytes memory)
    {
        require(_signature.length == 65, "sig len");
        bytes16 nonce16 = bytes16(uint128(_nonce));
        bytes20 to20 = bytes20(_to);
        return abi.encodePacked(_signature, nonce16, to20, _args);
    }

    function _fallbackEncodeEth(uint256 _ethAmount) internal pure returns (bytes memory) {
        bytes memory ethBytes = abi.encodePacked(uint80(_ethAmount));
        return ethBytes;
    }

    function _constructExecuteBytes(
        bytes memory _signature,
        uint128 _nonce,
        address _to,
        uint256 _value,
        bytes memory _args
    ) internal pure returns (bytes memory) {
        require(_signature.length == 65, "sig len");
        bytes16 nonce16 = bytes16(uint128(_nonce));
        bytes20 to20 = bytes20(_to);
        bytes32 value32 = bytes32(_value);
        return abi.encodePacked(_signature, nonce16, to20, value32, _args);
    }

    function _constructFallbackCalldata(bytes1 _selector, bytes memory _signature, uint128 _nonce, bytes memory _data)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(hex"00", _selector, _signature, _nonce, _data);
    }

    function _constructFallbackCalldata(
        uint128 _nonce,
        bytes memory _signature,
        address _outputContract,
        bytes memory _arguments
    ) internal pure returns (bytes memory) {
        bytes memory nonceBytes = abi.encodePacked(_nonce);
        if (nonceBytes.length < 16) {
            bytes memory padding = new bytes(16 - nonceBytes.length);
            nonceBytes = abi.encodePacked(nonceBytes, padding);
        }
        return abi.encodePacked(bytes1(0x00), bytes1(0x00), _signature, nonceBytes, _outputContract, _arguments);
    }

    function _constructFallbackCalldataWithETH(
        uint128 _nonce,
        bytes memory _signature,
        address _outputContract,
        uint256 _ethAmount,
        bytes memory _arguments
    ) internal pure returns (bytes memory) {
        bytes memory nonceBytes = abi.encodePacked(_nonce);
        if (nonceBytes.length < 16) {
            bytes memory padding = new bytes(16 - nonceBytes.length);
            nonceBytes = abi.encodePacked(nonceBytes, padding);
        }
        uint80 ethAmount80 = uint80(_ethAmount);
        bytes memory ethBytes = abi.encodePacked(ethAmount80);
        return
            abi.encodePacked(bytes1(0x00), bytes1(0x10), _signature, nonceBytes, _outputContract, ethBytes, _arguments);
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

    function _signSessionExecuteWithSender(
        uint256 _privateKey,
        address payable _publicKey,
        uint128 _counter,
        uint32 _deadline,
        address _sender,
        address _outputContract
    ) internal returns (bytes memory) {
        address signer = vm.addr(_privateKey);
        vm.startPrank(signer);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            _privateKey,
            MockDelegate(_publicKey).hashSessionExecution(_counter, uint32(_deadline), _sender, _outputContract)
        );
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();
        return signature;
    }

    function _constructSessionExecuteBytes(
        bytes memory _signature,
        uint128 _counter,
        uint32 _deadline,
        address _outputContract,
        uint256 _value,
        bytes memory _arguments
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(_signature, _counter, _deadline, _outputContract, _value, _arguments);
    }

    // Fallback builders for session paths (returning variants)
    function _constructFallbackSessionCalldataNoReturn(
        uint128 _counter,
        uint32 _deadline,
        bytes memory _signature,
        address _outputContract,
        bytes memory _arguments
    ) internal pure returns (bytes memory) {
        // selector 0x40 for executeSession without return
        bytes memory counterBytes = abi.encodePacked(_counter);
        if (counterBytes.length < 16) {
            bytes memory padding = new bytes(16 - counterBytes.length);
            counterBytes = abi.encodePacked(counterBytes, padding);
        }
        bytes4 deadline4 = bytes4(_deadline);
        // Insert a single padding byte between nonce and deadline; include 10-byte ETH amount (zero) before args
        bytes10 ethAmount10 = bytes10(0);
        return abi.encodePacked(
            bytes1(0x00),
            bytes1(0x40),
            _signature,
            counterBytes,
            bytes1(0x00),
            deadline4,
            _outputContract,
            ethAmount10,
            _arguments
        );
    }

    function _constructFallbackSessionCalldata(
        uint128 _counter,
        uint32 _deadline,
        bytes memory _signature,
        address _outputContract,
        bytes memory _arguments
    ) internal pure returns (bytes memory) {
        // selector 0x41 for executeSession with return
        bytes memory counterBytes = abi.encodePacked(_counter);
        if (counterBytes.length < 16) {
            bytes memory padding = new bytes(16 - counterBytes.length);
            counterBytes = abi.encodePacked(counterBytes, padding);
        }
        bytes4 deadline4 = bytes4(_deadline);
        // Insert a single padding byte between nonce and deadline; include 10-byte ETH amount (zero) before args
        bytes10 ethAmount10 = bytes10(0);
        return abi.encodePacked(
            bytes1(0x00),
            bytes1(0x41),
            _signature,
            counterBytes,
            bytes1(0x00),
            deadline4,
            _outputContract,
            ethAmount10,
            _arguments
        );
    }

    function _constructFallbackBatchSessionCalldata(
        uint128 _counter,
        uint32 _deadline,
        bytes memory _signature,
        address _outputContract,
        IBatchExecution.Call[] memory _calls
    ) internal pure returns (bytes memory) {
        // selector 0x51 for executeBatchSession with return
        bytes memory counterBytes = abi.encodePacked(_counter);
        if (counterBytes.length < 16) {
            bytes memory padding = new bytes(16 - counterBytes.length);
            counterBytes = abi.encodePacked(counterBytes, padding);
        }
        bytes4 deadline4 = bytes4(_deadline);
        // After output (20 bytes), pad 12 bytes so that the next word (length) sits at nonceEnd+41
        bytes12 pad12 = bytes12(0);
        bytes memory callsEncoded = abi.encode(_calls); // starts with length then elements
        return abi.encodePacked(
            bytes1(0x00),
            bytes1(0x51),
            _signature,
            counterBytes,
            bytes1(0x00),
            deadline4,
            _outputContract,
            pad12,
            callsEncoded
        );
    }

    function _constructFallbackArbitrarySessionCalldata(
        uint128 _counter,
        uint32 _deadline,
        bytes memory _signature,
        address _outputContract,
        bytes memory _arguments
    ) internal pure returns (bytes memory) {
        // selector 0x71 for executeSessionArbitrary with return
        bytes memory counterBytes = abi.encodePacked(_counter);
        if (counterBytes.length < 16) {
            bytes memory padding = new bytes(16 - counterBytes.length);
            counterBytes = abi.encodePacked(counterBytes, padding);
        }
        bytes4 deadline4 = bytes4(_deadline);
        return abi.encodePacked(
            bytes1(0x00), bytes1(0x71), _signature, counterBytes, bytes1(0x00), deadline4, _outputContract, _arguments
        );
    }

    function _constructFallbackArbitraryBatchSessionCalldata(
        uint128 _counter,
        uint32 _deadline,
        bytes memory _signature,
        IBatchExecution.Call[] memory _calls
    ) internal pure returns (bytes memory) {
        // selector 0x91 for executeBatchSessionArbitrary with return
        bytes memory counterBytes = abi.encodePacked(_counter);
        if (counterBytes.length < 16) {
            bytes memory padding = new bytes(16 - counterBytes.length);
            counterBytes = abi.encodePacked(counterBytes, padding);
        }
        bytes4 deadline4 = bytes4(_deadline);
        return abi.encodePacked(
            bytes1(0x00), bytes1(0x91), _signature, counterBytes, bytes1(0x00), deadline4, abi.encode(_calls)
        );
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
            vm.sign(_privateKey, MockDelegate(_publicKey).hashBatchExecution(_nonce, _calls));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();
        return signature;
    }

    function _signApproveThenExecute(
        uint256 _privateKey,
        address payable _publicKey,
        uint128 _nonce,
        address _erc20Contract,
        address _spender,
        uint256 _approveAmount,
        address _outputContract,
        uint256 _ethAmount,
        bytes memory _arguments
    ) internal returns (bytes memory) {
        address signer = vm.addr(_privateKey);
        vm.startPrank(signer);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            _privateKey,
            MockDelegate(_publicKey).hashApproveThenExecute(
                _nonce, _erc20Contract, _spender, _approveAmount, _outputContract, _ethAmount, _arguments
            )
        );
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();
        return signature;
    }

    function _constructApproveThenExecuteBytes(
        bytes memory _signature,
        uint128 _nonce,
        address _erc20Contract,
        address _spender,
        uint256 _approveAmount,
        address _outputContract,
        uint256 _ethAmount,
        bytes memory _arguments
    ) internal pure returns (bytes memory) {
        require(_signature.length == 65, "sig len");
        bytes16 nonce16 = bytes16(uint128(_nonce));
        bytes20 erc20Bytes = bytes20(_erc20Contract);
        bytes20 spenderBytes = bytes20(_spender);
        bytes32 approveAmountBytes = bytes32(_approveAmount);
        bytes20 outputBytes = bytes20(_outputContract);
        bytes32 ethAmountBytes = bytes32(_ethAmount);

        return abi.encodePacked(
            _signature, nonce16, erc20Bytes, spenderBytes, approveAmountBytes, outputBytes, ethAmountBytes, _arguments
        );
    }
}
