// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {PQClaimIssuer} from "../contracts/PQClaimIssuer.sol";
import {IMLDSA, ISLHDSA} from "../contracts/PQVerifier.sol";

/// @dev The cheatcodes these tests use, so they need no test library.
interface Vm {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest)
        external
        returns (uint8 v, bytes32 r, bytes32 s);
    function etch(address target, bytes calldata code) external;
    function store(address target, bytes32 slot, bytes32 value) external;
}

/// @dev Stands in for a PQ verify precompile: answers true for one exact call only, so an
///      accepted claim reached the precompile with exactly the canonical inputs.
contract ExactCallVerifier {
    fallback(bytes calldata input) external returns (bytes memory) {
        bytes32 expected;
        assembly {
            expected := sload(0)
        }
        return abi.encode(keccak256(input) == expected);
    }
}

/// @dev Revocation is keyed on the signature bytes, so a claim holder must not be able to
///      bring a revoked claim back by encoding the same signature differently.
contract PQClaimIssuerRevocationTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 private constant SECP256K1_ORDER =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    address private constant IDENTITY = address(0x1D);
    uint256 private constant TOPIC = 7;
    bytes private data = "kyc:passed";

    PQClaimIssuer private issuer;

    function setUp() public {
        issuer = new PQClaimIssuer();
    }

    function test_EcdsaClaimHasOneEncoding() public {
        uint256 signerKey = 0xA11CE;
        address signer = vm.addr(signerKey);
        issuer.addClaimKey(1, abi.encodePacked(signer));

        bytes32 digest = issuer.claimDigest(IDENTITY, TOPIC, data);
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, ethHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        bytes[] memory others = new bytes[](3);
        // v as 0/1, the high-s twin, and the same signature in the PQ wrapper as scheme 1
        others[0] = abi.encodePacked(r, s, v - 27);
        others[1] = abi.encodePacked(
            r, bytes32(SECP256K1_ORDER - uint256(s)), v == 27 ? uint8(28) : uint8(27));
        others[2] = abi.encode(uint256(1), abi.encodePacked(signer), sig);

        _assertOnlyCanonical(sig, others);
    }

    function test_SlhDsaClaimHasOneEncoding() public {
        bytes32 pk = keccak256("slh-dsa pk");
        bytes memory rawSig = new bytes(7856);
        rawSig[0] = 0x42;
        bytes32 digest = issuer.claimDigest(IDENTITY, TOPIC, data);
        _expectPrecompileCall(address(0x0404),
            abi.encodeCall(ISLHDSA.verify, (pk, bytes.concat(digest), rawSig)));

        _assertOnlyCanonicalWrapper(100, abi.encodePacked(pk), rawSig);
    }

    function test_MlDsaClaimHasOneEncoding() public {
        bytes memory pk = new bytes(1952);
        pk[0] = 0x07;
        bytes memory rawSig = new bytes(3309);
        rawSig[0] = 0x42;
        bytes32 digest = issuer.claimDigest(IDENTITY, TOPIC, data);
        _expectPrecompileCall(address(0x0405),
            abi.encodeCall(IMLDSA.verify, (pk, bytes.concat(digest), rawSig)));

        _assertOnlyCanonicalWrapper(101, pk, rawSig);
    }

    function _expectPrecompileCall(address precompile, bytes memory call) private {
        vm.etch(precompile, address(new ExactCallVerifier()).code);
        vm.store(precompile, bytes32(0), keccak256(call));
    }

    function _assertOnlyCanonicalWrapper(uint256 scheme, bytes memory pk, bytes memory rawSig)
        private
    {
        issuer.addClaimKey(scheme, pk);
        bytes memory sig = abi.encode(scheme, pk, rawSig);

        // a trailing word, and a spare word between the head and the pubkey
        bytes[] memory others = new bytes[](2);
        others[0] = bytes.concat(sig, bytes32(0));
        others[1] = abi.encodePacked(
            scheme, uint256(0x80), 0x80 + 0x20 + _padded(pk.length), bytes32(0),
            pk.length, pk, new bytes(_padded(pk.length) - pk.length),
            rawSig.length, rawSig, new bytes(_padded(rawSig.length) - rawSig.length));

        _assertOnlyCanonical(sig, others);
    }

    function _padded(uint256 length) private pure returns (uint256) {
        return (length + 31) / 32 * 32;
    }

    function _assertOnlyCanonical(bytes memory sig, bytes[] memory others) private {
        require(_accepted(sig), "canonical signature accepted");
        for (uint256 i = 0; i < others.length; i++) {
            require(!_accepted(others[i]), "other encoding refused");
        }

        issuer.revokeClaimBySignature(sig);

        require(!_accepted(sig), "revoked signature refused");
        for (uint256 i = 0; i < others.length; i++) {
            require(!_accepted(others[i]), "other encoding refused after revocation");
        }
    }

    function _accepted(bytes memory sig) private view returns (bool) {
        return issuer.isClaimValid(IDENTITY, TOPIC, sig, data);
    }
}
