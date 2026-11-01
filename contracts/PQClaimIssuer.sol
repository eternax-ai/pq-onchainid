// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IPQClaimIssuer} from "./IPQClaimIssuer.sol";
import {PQVerifier} from "./PQVerifier.sol";
import {SignatureSchemes} from "./SignatureSchemes.sol";

/// @title Scheme-agnostic ClaimIssuer for PQ-ONCHAINID
/// @notice Drop-in conceptual replacement for stock ONCHAINID ClaimIssuer.isClaimValid.
///         Token / Identity Registry / Trusted Issuers keep calling the same surface;
///         verification dispatches on scheme (ECDSA, SLH-DSA, ML-DSA).
///
/// @dev Signature encoding in `sig`:
///      - scheme 1 (ECDSA): raw 65-byte v/r/s (Ethereum personal_sign over claim digest)
///      - scheme 100/101: abi.encode(uint256 scheme, bytes pubkey, bytes rawSig)
///
///      Claim digest (all schemes): keccak256(abi.encode(identity, topic, data))
///
///      Precompiles at 0x0404 / 0x0405; see docs/precompiles.md.
contract PQClaimIssuer is IPQClaimIssuer {
    uint256 public constant CLAIM_PURPOSE = 3;

    address public owner;

    /// @dev keyId => active CLAIM key
    mapping(bytes32 => bool) private _claimKeys;

    /// @dev keccak256(sig) => revoked
    mapping(bytes32 => bool) private _revokedSignatures;

    /// @dev Optional: allow ECDSA keys as address (scheme 1) without storing full pubkey.
    mapping(address => bool) private _ecdsaClaimKeys;

    bool public ecdsaEnabled = true;
    bool public slhDsaEnabled = true;
    bool public mlDsaEnabled = true;

    error NotOwner();
    error UnsupportedScheme(uint256 scheme);
    error InvalidPubkey();
    error KeyNotFound();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // -------------------------------------------------------------------------
    // Key management
    // -------------------------------------------------------------------------

    function addClaimKey(uint256 scheme, bytes calldata pubkey) external onlyOwner {
        if (scheme == SignatureSchemes.ECDSA) {
            if (pubkey.length != 20) revert InvalidPubkey();
            address addr;
            assembly ("memory-safe") {
                addr := shr(96, calldataload(pubkey.offset))
            }
            _ecdsaClaimKeys[addr] = true;
            bytes32 kid = SignatureSchemes.keyId(scheme, pubkey);
            _claimKeys[kid] = true;
            emit ClaimKeyAdded(scheme, kid, pubkey);
            return;
        }

        if (scheme == SignatureSchemes.SLH_DSA_SHAKE_128S) {
            if (pubkey.length != SignatureSchemes.SLH_DSA_PK_LEN) revert InvalidPubkey();
        } else if (scheme == SignatureSchemes.ML_DSA_65) {
            if (pubkey.length != SignatureSchemes.ML_DSA_65_PK_LEN) revert InvalidPubkey();
        } else {
            revert UnsupportedScheme(scheme);
        }

        bytes32 keyId = SignatureSchemes.keyId(scheme, pubkey);
        _claimKeys[keyId] = true;
        emit ClaimKeyAdded(scheme, keyId, pubkey);
    }

    function revokeClaimKey(uint256 scheme, bytes calldata pubkey) external onlyOwner {
        bytes32 keyId = SignatureSchemes.keyId(scheme, pubkey);
        if (!_claimKeys[keyId]) revert KeyNotFound();
        _claimKeys[keyId] = false;

        if (scheme == SignatureSchemes.ECDSA && pubkey.length == 20) {
            address addr;
            assembly ("memory-safe") {
                addr := shr(96, calldataload(pubkey.offset))
            }
            _ecdsaClaimKeys[addr] = false;
        }

        emit ClaimKeyRevoked(scheme, keyId);
    }

    function isClaimKey(bytes32 keyId) external view returns (bool) {
        return _claimKeys[keyId];
    }

    function revokeClaimBySignature(bytes calldata sig) external onlyOwner {
        bytes32 sigHash = keccak256(sig);
        _revokedSignatures[sigHash] = true;
        emit ClaimRevoked(sigHash);
    }

    function isClaimRevoked(bytes calldata sig) public view returns (bool) {
        return _revokedSignatures[keccak256(sig)];
    }

    function setSchemeEnabled(uint256 scheme, bool enabled) external onlyOwner {
        if (scheme == SignatureSchemes.ECDSA) {
            ecdsaEnabled = enabled;
        } else if (scheme == SignatureSchemes.SLH_DSA_SHAKE_128S) {
            slhDsaEnabled = enabled;
        } else if (scheme == SignatureSchemes.ML_DSA_65) {
            mlDsaEnabled = enabled;
        } else {
            revert UnsupportedScheme(scheme);
        }
    }

    // -------------------------------------------------------------------------
    // Claim validation
    // -------------------------------------------------------------------------

    /// @inheritdoc IPQClaimIssuer
    function isClaimValid(
        address identity,
        uint256 topic,
        bytes calldata sig,
        bytes calldata data
    ) external view returns (bool) {
        if (isClaimRevoked(sig)) {
            return false;
        }

        bytes32 digest = claimDigest(identity, topic, data);

        // Bare ECDSA (stock ONCHAINID wire format)
        if (sig.length == 65) {
            if (!ecdsaEnabled) {
                return false;
            }
            address recovered = PQVerifier.recoverEcdsa(digest, sig);
            if (recovered == address(0)) {
                return false;
            }
            return _ecdsaClaimKeys[recovered];
        }

        // PQ: abi.encode(scheme, pubkey, rawSig). ECDSA has only the 65-byte form above.
        (uint256 scheme, bytes memory pubkey, bytes memory rawSig) =
            abi.decode(sig, (uint256, bytes, bytes));

        // Revocation is keyed on the signature bytes, and abi.decode also accepts
        // trailing bytes and other offsets, so only the canonical encoding counts.
        if (keccak256(sig) != keccak256(abi.encode(scheme, pubkey, rawSig))) {
            return false;
        }

        bytes32 keyId = SignatureSchemes.keyId(scheme, pubkey);
        if (!_claimKeys[keyId]) {
            return false;
        }

        if (scheme == SignatureSchemes.SLH_DSA_SHAKE_128S) {
            if (!slhDsaEnabled || pubkey.length != SignatureSchemes.SLH_DSA_PK_LEN) {
                return false;
            }
            bytes32 pk;
            assembly ("memory-safe") {
                pk := mload(add(pubkey, 32))
            }
            return PQVerifier.verifySlhDsa(pk, bytes.concat(digest), rawSig);
        }

        if (scheme == SignatureSchemes.ML_DSA_65) {
            if (!mlDsaEnabled) {
                return false;
            }
            return PQVerifier.verifyMlDsa(pubkey, bytes.concat(digest), rawSig);
        }

        return false;
    }

    /// @notice Canonical claim message hashed by all schemes.
    function claimDigest(address identity, uint256 topic, bytes calldata data)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(identity, topic, data));
    }
}
