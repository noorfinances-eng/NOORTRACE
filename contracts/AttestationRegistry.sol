// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title AttestationRegistry
/// @notice Anchors the fingerprint of a document an organization issues:
///         a diploma, an internship certificate, an attestation. The
///         organization signs off-chain; anyone relays and pays the gas
///         (the hub does). The chain keeps the fingerprint, the issuer, the
///         document type and two timestamps. Never the file, never a name.
///
/// @dev The digest is bound to the chain, to this registry, to a purpose tag,
///      to the fingerprint and to the document type, then EIP-191 prefixed
///      (the same discipline as CuratorSet and PoSSRegistry). The relayer
///      announces the issuer and the contract checks the signature against
///      that address: a relayer that altered the type, the fingerprint or the
///      issuer gets a refusal, never a record under a wrong name. A
///      fingerprint anchors once, so a signature cannot be replayed; the
///      revocation digest carries its own tag, so an anchoring signature can
///      never revoke.
contract AttestationRegistry {
    struct Record {
        address issuer;
        bytes32 docType;
        uint64 issuedAt;
        uint64 revokedAt;
    }

    struct Signature {
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    string private constant TAG_ANCHOR = "noor-attestation-ancre";
    string private constant TAG_REVOKE = "noor-attestation-revoque";

    mapping(bytes32 => Record) private records;

    event Anchored(bytes32 indexed fingerprint, address indexed issuer, bytes32 docType);
    event Revoked(bytes32 indexed fingerprint, address indexed issuer);

    error BadFingerprint();
    error AlreadyAnchored();
    error AlreadyRevoked();
    error Unknown();
    error NotTheIssuer();

    /// @notice The digest the organization signs (EIP-191) to anchor `fingerprint` as `docType`.
    function anchorDigest(bytes32 fingerprint, bytes32 docType) public view returns (bytes32) {
        return keccak256(abi.encodePacked(block.chainid, address(this), TAG_ANCHOR, fingerprint, docType));
    }

    /// @notice The digest the organization signs (EIP-191) to revoke `fingerprint`.
    function revokeDigest(bytes32 fingerprint) public view returns (bytes32) {
        return keccak256(abi.encodePacked(block.chainid, address(this), TAG_REVOKE, fingerprint));
    }

    /// @notice Anchor `fingerprint` as `docType`, issued by `issuer`, whose signature over
    ///         `anchorDigest` is `sig`. Relayed by anyone.
    function anchor(bytes32 fingerprint, bytes32 docType, address issuer, Signature calldata sig) external {
        if (fingerprint == bytes32(0)) revert BadFingerprint();
        if (records[fingerprint].issuer != address(0)) revert AlreadyAnchored();
        _requireSigner(anchorDigest(fingerprint, docType), sig, issuer);
        records[fingerprint] = Record({ issuer: issuer, docType: docType, issuedAt: uint64(block.timestamp), revokedAt: 0 });
        emit Anchored(fingerprint, issuer, docType);
    }

    /// @notice Revoke `fingerprint`; only its issuer's signature over `revokeDigest` is accepted.
    function revoke(bytes32 fingerprint, Signature calldata sig) external {
        Record storage rec = records[fingerprint];
        if (rec.issuer == address(0)) revert Unknown();
        if (rec.revokedAt != 0) revert AlreadyRevoked();
        _requireSigner(revokeDigest(fingerprint), sig, rec.issuer);
        rec.revokedAt = uint64(block.timestamp);
        emit Revoked(fingerprint, rec.issuer);
    }

    /// @notice The record of `fingerprint`; every field zero when unknown.
    function lookup(bytes32 fingerprint) external view returns (Record memory) {
        return records[fingerprint];
    }

    function isAnchored(bytes32 fingerprint) external view returns (bool) {
        return records[fingerprint].issuer != address(0);
    }

    function _requireSigner(bytes32 digest, Signature calldata sig, address expected) internal pure {
        bytes32 prefixed = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        address signer = ecrecover(prefixed, sig.v, sig.r, sig.s);
        if (signer == address(0) || expected == address(0) || signer != expected) revert NotTheIssuer();
    }
}
