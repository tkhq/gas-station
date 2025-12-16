// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {LibClone} from "solady/utils/LibClone.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
import {TKSmartWalletDelegate} from "./TKSmartWalletDelegate.sol";
import {PublicKey} from "../structs/PublicKey.sol";
import {RuleSet} from "../structs/RuleSet.sol";
import {TransientSignature} from "../structs/TransientSignature.sol";
import {ITKSmartWalletFactory} from "../interfaces/ITKSmartWalletFactory.sol";

/// @notice Factory contract for creating deterministic clonable proxies of TKSmartWalletDelegate.
/// @dev Uses Solady's LibClone to deploy minimal proxy clones (EIP-1167) with CREATE2.
/// The factory acts as the arbiter contract for all created wallets.
contract TKSmartWalletFactory is ITKSmartWalletFactory {
    error InvalidPublicKeyIndex();
    error InvalidPublicKeyLengthForRemoval();
    error InvalidAddressIndex();
    error InvalidAddressLengthForRemoval();
    error InvalidMOfForRemoval();
    error InvalidPublicKeyLengthForAddition();
    error InvalidAddressLengthForAddition();

    error InvalidArrayLength();
    error InvalidN();
    error InvalidMOf();
    error InvalidSignatureLength();
    error InvalidPasskeyOrAddressIndex();

    error PassKeyIndexMustBeLessThan128();
    error AddressIndexMustBeGreaterThan127AndNot255();

    error InvalidSignaturesLengthForSet();

    //IMMUTABLES

    address public immutable IMPLEMENTATION;
    uint8 public constant MAX_ARRAY_LENGTH = 127;
    uint8 public constant MAX_M_OF = 64;
    address internal constant P256_VERIFY = address(0x100);

    event WalletCreatedWithRuleSet(address indexed wallet, address indexed creator, RuleSet ruleSet, address _creator, bytes32 _salt);

    event RuleSetPublicKeyAdded(address indexed wallet, bytes32 x, bytes32 y);
    event RuleSetAddressAdded(address indexed wallet, address addedAddress);
    event RuleSetMOfUpdated(address indexed wallet, uint8 mOf);
    event RuleSetPublicKeysReplaced(address indexed wallet, PublicKey[] publicKeys, uint8 n);
    event RuleSetAddressesReplaced(address indexed wallet, address[] addresses, uint8 n);

    mapping(bytes32 => address) public publicKeyToAddress;

    mapping(address => RuleSet) public ruleSets;

    mapping

    //CONSTRUCTOR

    /// @dev Deploys a TKSmartWalletDelegate implementation with this factory as the arbiter.
    constructor() {
        IMPLEMENTATION = address(new TKSmartWalletDelegate(address(this)));
    }

    //DEPLOY FUNCTIONS

    function createWallet(bytes32 _x, bytes32 _y) external returns (address instance) {
        bytes32 salt = _packBytes32sToSalt(_x, _y);
        PublicKey[] memory publicKeysArray = new PublicKey[](1);
        publicKeysArray[0] = PublicKey({x: _x, y: _y});
        return _createWallet(1, publicKeysArray, new address[](0), address(0), salt);
    }

    function createWallet(address _address) external returns (address instance) {
        address[] memory addresses = new address[](1);
        addresses[0] = _address;
        return _createWallet(1, new PublicKey[](0), addresses, address(0), keccak256(abi.encodePacked(_address)));
    }

    function createWallet(uint8 _mOf, PublicKey[] memory _publicKeys, address[] memory _addresses, address _creator, bytes32 _salt)
        external
        returns (address instance)
    {
        return _createWallet(_mOf, _publicKeys, _addresses, _creator, _salt);
    }

    function _createWallet(uint8 _mOf, PublicKey[] memory _publicKeys, address[] memory _addresses, address _creator, bytes32 _salt) internal returns (address instance) {
        // allow deterministic address generation by the creator and can limit that a creator can make sure no one else makes a wallet with the same salt
        // if creator is address(0), then any address can create a wallet with the same salt and initialization data
        if (_creator == address(0)) {
            _salt = keccak256(abi.encodePacked(abi.encodePacked(_mOf, _publicKeys, _addresses, _creator, _salt)));
        } else if (_creator == msg.sender) {
            _salt = keccak256(abi.encodePacked(_creator, _salt)); // otherwise just use the creator and salt provided by the caller
        } else {
            revert InvalidCreator();
        }

        if (_publicKeys.length > MAX_ARRAY_LENGTH || _addresses.length > MAX_ARRAY_LENGTH) {
            revert InvalidArrayLength();
        }
        uint8 n = uint8(_publicKeys.length) + uint8(_addresses.length);
        if (n == 0) {
            revert InvalidN();
        }
        if (_mOf > n || _mOf == 0) {
            revert InvalidMOf();
        }

        RuleSet memory ruleSet =
            RuleSet({mOf: _mOf, n: n, publicKeys: _publicKeys, addresses: _addresses});
        instance = LibClone.cloneDeterministic(IMPLEMENTATION, _salt);
        ruleSets[instance] = ruleSet;
        emit WalletCreatedWithRuleSet(instance, msg.sender, ruleSet, _creator, _salt);
    }

    //VIEW FUNCTIONS
    function predictWalletAddress(bytes32 _x, bytes32 _y) external view returns (address predicted) {
        bytes32 salt = _packBytes32sToSalt(_x, _y);
        predicted = LibClone.predictDeterministicAddress(IMPLEMENTATION, salt, address(this));
    }

    function initCodeHash() external view returns (bytes32 hash) {
        hash = LibClone.initCodeHash(IMPLEMENTATION);
    }

    /// @dev Returns the wallet address for a given passkey public key (x, y), or address(0) if none.
    function getAddressForPublicKey(bytes32 _x, bytes32 _y) external view returns (address) {
        return publicKeyToAddress[keccak256(abi.encodePacked(_x, _y))];
    }

    function getAddressForAddress(address _address) external view returns (address) {
        return publicKeyToAddress[keccak256(abi.encodePacked(_address))];
    }

    //INTERNAL FUNCTIONS

    function _packBytes32sToSalt(bytes32 _x, bytes32 _y) internal pure returns (bytes32 salt) {
        salt = keccak256(abi.encodePacked(_x, _y));
    }

    //IArbiter

    function validateSignature(address _target, bytes32 _hash, bytes calldata _signature) external view returns (bool) {
        return _validateSignatureForTarget(_target, _hash, _signature);
    }

    function validateSignature(bytes32 _hash, bytes calldata _signature) public view returns (bool) {
        return _validateSignatureForTarget(msg.sender, _hash, _signature);
    }

    function _validateSignatureForTarget(address _target, bytes32 _hash, bytes calldata _signature)
        internal
        view
        returns (bool)
    {
        RuleSet memory ruleSet = ruleSets[_target];

        if (ruleSet.n == 1 && ruleSet.mOf == 1) {
            // case of one of one, assume 65 byte calldata signature
            if (ruleSet.publicKeys.length > 0) {
                return _validatePasskeySignature(ruleSet.publicKeys[0], _hash, _signature);
            }
            if (ruleSet.addresses.length > 0) {
                return SignatureCheckerLib.isValidSignatureNowCalldata(ruleSet.addresses[0], _hash, _signature);
            }
            return false;
        } else if (ruleSet.mOf > 1) {
            uint8 validSignatures = 0;
            for (uint8 i = 0; i < _signature.length && i < ruleSet.mOf && validSignatures < ruleSet.mOf; i++) {
                uint8 index = uint8(_signature[i]);
                if (index == 255) {
                    //FF is the end of the signature
                    break;
                }
                if (index < 128) {
                    // then it is a passkey signature
                    (bytes32 first32, bytes32 second32) = getTransientPassKeySignature(_target, index);
                    if (first32 == 0 && second32 == 0) {
                        // if null just continue
                        continue;
                    }
                    if (
                        _validatePasskeySignature(ruleSet.publicKeys[index], _hash, first32, second32)
                            && validSignatures < ruleSet.mOf
                    ) {
                        validSignatures++;
                    }
                } else {
                    // then it is a address signature
                    uint8 addressIndex = index - MAX_ARRAY_LENGTH; //127
                    (bytes32 r, bytes32 s, bytes1 v) = getTransientAddressSignature(_target, addressIndex);
                    if (r == 0 && s == 0 && v == 0) {
                        // if null just continue
                        continue;
                    }
                    if (
                        SignatureCheckerLib.isValidSignatureNow(
                            ruleSets[_target].addresses[addressIndex], _hash, uint8(v), r, s
                        )
                    ) {
                        validSignatures++;
                    }
                }
            }
            return validSignatures >= ruleSet.mOf;
        }

        return false;
    }

    function _validatePasskeySignature(PublicKey memory _publicKey, bytes32 _hash, bytes calldata _signature)
        internal
        view
        returns (bool)
    {
        bytes32 messageHash = sha256(abi.encodePacked(_hash));
        bytes memory input =
            abi.encodePacked(messageHash, _signature[0:32], _signature[32:64], _publicKey.x, _publicKey.y);
        (bool success, bytes memory result) = P256_VERIFY.staticcall(input);
        return success && result.length == 32 && abi.decode(result, (uint256)) == 1;
    }

    function _validatePasskeySignature(PublicKey memory _publicKey, bytes32 _hash, bytes32 _first32, bytes32 _second32)
        internal
        view
        returns (bool)
    {
        bytes32 messageHash = sha256(abi.encodePacked(_hash));
        bytes memory input = abi.encodePacked(messageHash, _first32, _second32, _publicKey.x, _publicKey.y);
        (bool success, bytes memory result) = P256_VERIFY.staticcall(input);
        return success && result.length == 32 && abi.decode(result, (uint256)) == 1;
    }

    // External functions to set transient storage

    function setTransientSignatures(address _target, TransientSignature[] calldata _signatures) external returns (bytes memory) {
        if(_signatures.length == 0 || _signatures.length > 65) {
            revert InvalidSignaturesLengthForSet();
        }
        bytes memory signature = new bytes(65);
        uint8 i = 0;
        for (; i < _signatures.length; i++) {
            if (_signatures[i].signature.length == 65) { // address signature 
                _setTransientAddressSignature(_target, _signatures[i].index + 128, _signatures[i].signature);
                signature[i] = bytes1( _signatures[i].index + 128);
            } else if (_signatures[i].signature.length == 64) { // passkey signature
                _setTransientPassKeySignature(_target, _signatures[i].index, _signatures[i].signature);
                signature[i] = bytes1(_signatures[i].index);
            } else {
                revert InvalidSignatureLength(); 
            }
        }
        if (i < 64) { // if not all 65 slots are used, then set the slot to FF to indicate the end of the signature
            signature[i] = bytes1(0xFF); // FF is the end of the signature
        }
        return signature;
    }

    function _setTransientSignature(address _target, uint8 _index, bytes calldata _signature) internal {
        if (_signature.length != 65) {
            _setTransientAddressSignature(_target, _index, _signature);
        } else if (_signature.length == 64) {
            _setTransientPassKeySignature(_target, _index, _signature);
        } else {
            revert InvalidSignatureLength(); 
        }
    }

    function _setTransientPassKeySignature(address _target, uint8 _index, bytes calldata _signature) internal {
        if (_index > 127) {
            revert PassKeyIndexMustBeLessThan128();
        }
        bytes32 key = keccak256(abi.encodePacked(_target, "passkey", _index));
        assembly ("memory-safe") {
            // Store first 32 bytes of signature in key slot
            tstore(key, calldataload(add(_signature.offset, 0)))
            // Store second 32 bytes of signature in key + 1 slot
            tstore(add(key, 1), calldataload(add(_signature.offset, 32)))
        }
    }

    function getTransientPassKeySignature(address _target, uint8 _index) public view returns (bytes32, bytes32) {
        if (_index > 127) {
            revert PassKeyIndexMustBeLessThan128();
        }
        bytes32 key = keccak256(abi.encodePacked(_target, "passkey", _index));
        bytes32 first32;
        bytes32 second32;
        assembly ("memory-safe") {
            // Load first 32 bytes of signature from key slot
            first32 := tload(key)
            // Load second 32 bytes of signature from key + 1 slot
            second32 := tload(add(key, 1))
        }
        return (first32, second32);
    }

    function setTransientAddressSignature(address _target, uint8 _index, bytes calldata _signature) external {
        _setTransientAddressSignature(_target, _index, _signature);
    }

    function _setTransientAddressSignature(address _target, uint8 _index, bytes calldata _signature) internal {
        if (_index < 128 || _index == 255) {
            revert AddressIndexMustBeGreaterThan127AndNot255();
        }
        bytes32 key = keccak256(abi.encodePacked(_target, "address", _index));
        assembly ("memory-safe") {
            // Store first 32 bytes of signature in key slot
            tstore(key, calldataload(add(_signature.offset, 0)))
            // Store second 32 bytes of signature in key + 1 slot
            tstore(add(key, 1), calldataload(add(_signature.offset, 32)))
            // Store last byte (65th byte) in key + 2 slot (padded to 32 bytes)
            let lastByte := calldataload(add(_signature.offset, 64))
            tstore(add(key, 2), shr(248, lastByte))
        }
    }

    function getTransientAddressSignature(address _target, uint8 _index)
        public
        view
        returns (bytes32 r, bytes32 s, bytes1 v)
    {
        if (_index < 128 || _index == 255) {
            revert AddressIndexMustBeGreaterThan127AndNot255();
        }
        bytes32 key = keccak256(abi.encodePacked(_target, "address", _index));
        assembly ("memory-safe") {
            r := tload(key)
            s := tload(add(key, 1))
            v := tload(add(key, 2)) // todo, check if this reads the most significant byte or least significant byte
        }
    }

    function addPublicKey(bytes32 _x, bytes32 _y) external {
        ruleSets[msg.sender].publicKeys.push(PublicKey({x: _x, y: _y}));
        if (ruleSets[msg.sender].publicKeys.length > MAX_ARRAY_LENGTH) {
            revert InvalidPublicKeyLengthForAddition();
        }
        ruleSets[msg.sender].n++;
        emit RuleSetPublicKeyAdded(msg.sender, _x, _y);
    }

    function addAddress(address _address) external {
        ruleSets[msg.sender].addresses.push(_address);
        if (ruleSets[msg.sender].addresses.length > MAX_ARRAY_LENGTH) {
            revert InvalidAddressLengthForAddition();
        }
        ruleSets[msg.sender].n++;
        emit RuleSetAddressAdded(msg.sender, _address);
    }

    function setMOf(uint8 _mOf) external {
        if (_mOf > ruleSets[msg.sender].n || _mOf > MAX_M_OF || _mOf == 0) {
            revert InvalidMOf();
        }
        ruleSets[msg.sender].mOf = _mOf;
        emit RuleSetMOfUpdated(msg.sender, _mOf);
    }


    function replacePublicKeys(PublicKey[] calldata _publicKeys) external {
        uint8 pubKeyLen = uint8(_publicKeys.length);
        if (pubKeyLen > MAX_ARRAY_LENGTH) {
            revert InvalidPublicKeyLengthForAddition();
        }

        RuleSet storage rs = ruleSets[msg.sender];
        uint8 n = rs.n - uint8(rs.publicKeys.length) + pubKeyLen;
        if (n == 0) {
            revert InvalidN();
        }
        if (rs.mOf > n) {
            revert InvalidMOfForRemoval();
        }

        delete rs.publicKeys;
        rs.publicKeys = _publicKeys;
        rs.n = n;

        emit RuleSetPublicKeysReplaced(msg.sender, _publicKeys, n);
    }

    function replaceAddresses(address[] calldata _addresses) external {
        uint8 addrLen = uint8(_addresses.length);
        if (addrLen > MAX_ARRAY_LENGTH) {
            revert InvalidAddressLengthForAddition();
        }

        RuleSet storage rs = ruleSets[msg.sender];
        uint8 n = rs.n - uint8(rs.addresses.length) + addrLen;
        if (n == 0) {
            revert InvalidN();
        }
        if (rs.mOf > n) {
            revert InvalidMOfForRemoval();
        }

        delete rs.addresses;
        rs.addresses = _addresses;
        rs.n = n;

        emit RuleSetAddressesReplaced(msg.sender, _addresses, n);
    }
}
