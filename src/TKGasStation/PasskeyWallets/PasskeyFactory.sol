// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {LibClone} from "solady/utils/LibClone.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
import {PasskeyDelegate} from "./PasskeyDelegate.sol";
import {IPasskeyArbiter} from "./IPasskeyArbiter.sol";

/// @notice Factory contract for creating deterministic clonable proxies of PasskeyDelegate.
/// @dev Uses Solady's LibClone to deploy minimal proxy clones (EIP-1167) with CREATE2.
/// The factory acts as the arbiter contract for all created wallets.
contract PasskeyFactory is IPasskeyArbiter {
    error InvalidMBurn();
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

    //IMMUTABLES

    address public immutable IMPLEMENTATION;
    uint8 public constant MAX_ARRAY_LENGTH = 127;
    uint8 public constant MAX_M_OF = 64;
    address internal constant P256_VERIFY = address(0x100);

    event WalletCreated(address indexed wallet, address indexed creator, bytes32 x, bytes32 y);
    event WalletCreatedFromAddress(address indexed wallet, address indexed creator, address _address);
    event WalletCreatedWithRuleSet(address indexed wallet, address indexed creator, RuleSet ruleSet);

    event RuleSetPublicKeyAdded(address indexed wallet, bytes32 x, bytes32 y);
    event RuleSetAddressAdded(address indexed wallet, address addedAddress);
    event RuleSetMOfUpdated(address indexed wallet, uint8 mOf);
    event RuleSetMBurnUpdated(address indexed wallet, uint8 mBurn);
    event RuleSetPublicKeysReplaced(address indexed wallet, PublicKey[] publicKeys, uint8 n);
    event RuleSetAddressesReplaced(address indexed wallet, address[] addresses, uint8 n);

    struct PublicKey {
        bytes32 x;
        bytes32 y;
    }

    struct RuleSet {
        uint8 mOf;
        uint8 n;
        uint8 mBurn;
        PublicKey[] publicKeys;
        address[] addresses;
    }

    mapping(bytes32 => address) internal publicKeyToAddress;

    mapping(address => RuleSet) public ruleSets;

    //CONSTRUCTOR

    /// @dev Deploys a PasskeyDelegate implementation with this factory as the arbiter.
    constructor() {
        IMPLEMENTATION = address(new PasskeyDelegate(address(this)));
    }

    //DEPLOY FUNCTIONS

    function createWallet(bytes32 _x, bytes32 _y) external returns (address instance) {
        bytes32 salt = _packBytes32sToSalt(_x, _y);
        instance = LibClone.cloneDeterministic(IMPLEMENTATION, salt);
        PublicKey memory publicKey = PublicKey({x: _x, y: _y});
        publicKeyToAddress[keccak256(abi.encodePacked(_x, _y))] = instance;
        PublicKey[] memory publicKeysArray = new PublicKey[](1);
        publicKeysArray[0] = publicKey;
        ruleSets[instance] = RuleSet({mOf: 1, n: 1, mBurn: 1, publicKeys: publicKeysArray, addresses: new address[](0)});
        emit WalletCreated(instance, msg.sender, _x, _y);
    }

    function createWallet(address _address) external returns (address instance) {
        bytes32 salt = keccak256(abi.encodePacked(_address));
        instance = LibClone.cloneDeterministic(IMPLEMENTATION, salt);
        publicKeyToAddress[keccak256(abi.encodePacked(_address))] = instance;
        ruleSets[instance] =
            RuleSet({mOf: 1, n: 1, mBurn: 1, publicKeys: new PublicKey[](0), addresses: new address[](1)});
        ruleSets[instance].addresses[0] = _address;
        emit WalletCreatedFromAddress(instance, msg.sender, _address);
    }

    function createWallet(uint8 _mOf, uint8 _mBurn, PublicKey[] memory _publicKeys, address[] memory _addresses)
        external
        returns (address instance)
    {
        if (_publicKeys.length > MAX_ARRAY_LENGTH || _addresses.length > MAX_ARRAY_LENGTH) {
            revert InvalidArrayLength();
        }
        uint8 n = uint8(_publicKeys.length) + uint8(_addresses.length);
        if (n == 0) {
            revert InvalidN();
        }
        if (_mOf > n || _mBurn > n || _mOf == 0 || _mBurn == 0) {
            revert InvalidMOf();
        }

        RuleSet memory ruleSet =
            RuleSet({mOf: _mOf, n: n, mBurn: _mBurn, publicKeys: _publicKeys, addresses: _addresses});
        instance = LibClone.clone(IMPLEMENTATION);
        ruleSets[instance] = ruleSet;
        emit WalletCreatedWithRuleSet(instance, msg.sender, ruleSet);
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

    //IPasskeyArbiter

    function validateSignature(bytes32 _hash, bytes calldata _signature) external view returns (bool) {
        RuleSet memory ruleSet = ruleSets[msg.sender];

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
                    (bytes32 first32, bytes32 second32) = getTransientPassKeySignature(msg.sender, index);
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
                    (bytes32 r, bytes32 s, bytes1 v) = getTransientAddressSignature(msg.sender, addressIndex);
                    if (r == 0 && s == 0 && v == 0) {
                        // if null just continue
                        continue;
                    }
                    if (
                        SignatureCheckerLib.isValidSignatureNow(
                            ruleSets[msg.sender].addresses[addressIndex], _hash, uint8(v), r, s
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

    function setTransientPassKeySignature(address _target, uint8 _index, bytes calldata _signature) external {
        bytes32 key = keccak256(abi.encodePacked(_target, "passkey", _index));
        assembly ("memory-safe") {
            // Store first 32 bytes of signature in key slot
            tstore(key, calldataload(add(_signature.offset, 0)))
            // Store second 32 bytes of signature in key + 1 slot
            tstore(add(key, 1), calldataload(add(_signature.offset, 32)))
        }
    }

    function getTransientPassKeySignature(address _target, uint8 _index) public view returns (bytes32, bytes32) {
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

    function setMBurn(uint8 _mBurn) external {
        if (_mBurn > ruleSets[msg.sender].n || _mBurn > MAX_M_OF || _mBurn == 0) {
            revert InvalidMBurn();
        }
        ruleSets[msg.sender].mBurn = _mBurn;
        emit RuleSetMBurnUpdated(msg.sender, _mBurn);
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
        if (rs.mOf > n || rs.mBurn > n) {
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
        if (rs.mOf > n || rs.mBurn > n) {
            revert InvalidMOfForRemoval();
        }

        delete rs.addresses;
        rs.addresses = _addresses;
        rs.n = n;

        emit RuleSetAddressesReplaced(msg.sender, _addresses, n);
    }
}
