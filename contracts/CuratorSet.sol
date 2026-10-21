// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title CuratorSet
/// @notice Minimal curator registry + threshold for PoSS v0 (application layer, not consensus).
///
/// @dev Design note: Pausable is intentionally NOT inherited and there is no
///      pause/unpause switch. This is a deliberate design decision, not an
///      omission:
///        - PoSS sits at the application layer and must minimize discretionary
///          halt authority over its operational surface.
///        - Curator/threshold changes already provide an explicit governance
///          surface (onlyAdmin) for legitimate emergency procedures.
///        - Adding a hidden pause switch would create an unaudited soft-halt
///          path and weaken the immutability assumptions external auditors
///          and operators rely on.
///      Emergency controls MUST go through explicit admin/governance actions
///      (setThreshold / addCurator / removeCurator / proposeAdmin+acceptAdmin),
///      not a pause.
///
/// @dev Admin transfer follows a 2-step propose+accept pattern (proposeAdmin
///      then acceptAdmin) so that an admin key cannot be transferred to an
///      address that does not (or cannot) control acceptance. The direct
///      setAdmin function has been removed.
///
/// @dev removeCurator does NOT silently lower the threshold. If removing a
///      curator would make the configured threshold exceed the remaining
///      curator count, the call reverts with ThresholdWouldExceedCurators
///      and the admin must explicitly call setThreshold first.
///
/// @dev SIGNED ADMIN OPERATIONS (2026-08-30). Every admin action also exists in
///      a `…Signed` form: the admin SIGNS an EIP-191 authorization and anyone
///      relays it, paying the gas. The relayer holds no authority — it carries
///      a decision it can neither forge nor alter.
///
///      This exists because of who the admin is meant to be. A curator set now
///      belongs to ONE organization (see CuratorSetRegistry), and that
///      organization's key is generated in its owner's browser and downloaded —
///      the server never sees it. Such an address holds no NUR and therefore
///      cannot send a transaction at all. Without a relayed path, the only
///      workable admin would be the shared deployer key, and the isolation
///      would hold between organizations but not against the Foundation.
///
///      `acceptAdminSigned` matters as much as the rest: `acceptAdmin` requires
///      a call FROM the new admin, which an unfunded address cannot make. Take
///      it away and the hand-over is impossible, so the deployer stays admin
///      forever and the whole point is lost.
///
///      Replay is closed on four axes, all inside the signed digest: `chainid`
///      (one chain), `address(this)` (one curator set — two organizations may
///      share a person at their head), the operation tag (an addCurator
///      authorization cannot be presented as a removeCurator), and a sequential
///      `opNonce` (an authorization is spent exactly once).
contract CuratorSet {
    mapping(address => bool) private _isCurator;
    uint256 private _curatorCount;
    uint256 private _threshold;
    address public admin;
    address public pendingAdmin;

    event CuratorAdded(address indexed curator);
    event CuratorRemoved(address indexed curator);
    event ThresholdUpdated(uint256 threshold);
    event AdminProposed(address indexed currentAdmin, address indexed pendingAdmin);
    event AdminAccepted(address indexed previousAdmin, address indexed newAdmin);

    // Custom errors (used alongside legacy string requires to preserve
    // existing test expectations on unchanged paths).
    error ThresholdWouldExceedCurators(uint256 threshold, uint256 remainingCurators);
    error NotPendingAdmin();
    error ZeroAddress();
    error NotAuthorized();
    error BadNonce(uint256 expected, uint256 got);

    struct Signature {
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    /// @notice Operation tags. Exposed so no caller has to re-type the string
    ///         that produced them — a mistyped tag is a signature that will
    ///         never verify, with nothing to say why.
    bytes32 public constant OP_ADD_CURATOR = keccak256("CuratorSet.addCurator");
    bytes32 public constant OP_REMOVE_CURATOR = keccak256("CuratorSet.removeCurator");
    bytes32 public constant OP_SET_THRESHOLD = keccak256("CuratorSet.setThreshold");
    bytes32 public constant OP_ACCEPT_ADMIN = keccak256("CuratorSet.acceptAdmin");
    bytes32 public constant OP_PROPOSE_ADMIN = keccak256("CuratorSet.proposeAdmin");

    /// @notice Sequential nonce for signed admin operations. One authorization,
    ///         one use, in order.
    uint256 public opNonce;

    event AdminOpRelayed(bytes32 indexed op, address indexed relayer, uint256 nonce);

    modifier onlyAdmin() {
        require(msg.sender == admin, "CuratorSet: not admin");
        _;
    }

    /// @notice The digest the admin must sign for `op` on `arg` at `nonce`.
    /// @dev Given by the contract on purpose: the owner signs in a browser, and
    ///      a browser that recomputed this itself would turn any encoding
    ///      divergence into refusals nobody could trace back to their cause.
    function adminOpDigest(bytes32 op, bytes32 arg, uint256 nonce) public view returns (bytes32) {
        return keccak256(abi.encodePacked(block.chainid, address(this), op, arg, nonce));
    }

    function _consume(bytes32 op, bytes32 arg, uint256 nonce, Signature calldata sig, address expected) internal {
        if (nonce != opNonce) revert BadNonce(opNonce, nonce);
        bytes32 digest = adminOpDigest(op, arg, nonce);
        bytes32 prefixed = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        address signer = ecrecover(prefixed, sig.v, sig.r, sig.s);
        if (signer == address(0) || signer != expected) revert NotAuthorized();
        opNonce = nonce + 1;
        emit AdminOpRelayed(op, msg.sender, nonce);
    }

    /// @notice `addCurator`, authorized by the admin's signature, relayed by anyone.
    function addCuratorSigned(address curator, uint256 nonce, Signature calldata sig) external {
        _consume(OP_ADD_CURATOR, bytes32(uint256(uint160(curator))), nonce, sig, admin);
        _addCurator(curator);
    }

    /// @notice `removeCurator`, authorized by the admin's signature.
    function removeCuratorSigned(address curator, uint256 nonce, Signature calldata sig) external {
        _consume(OP_REMOVE_CURATOR, bytes32(uint256(uint160(curator))), nonce, sig, admin);
        _removeCurator(curator);
    }

    /// @notice `setThreshold`, authorized by the admin's signature.
    function setThresholdSigned(uint256 t, uint256 nonce, Signature calldata sig) external {
        _consume(OP_SET_THRESHOLD, bytes32(t), nonce, sig, admin);
        _setThreshold(t);
    }

    /// @notice `proposeAdmin`, authorized by the sitting admin's signature and
    ///         relayed — the exit the one-way door lacked.
    /// @dev MEASURED 2026-08-30 on the pilot: an organization completed the
    ///      hand-over, and `proposeAdmin` being the ONLY admin operation
    ///      without a signed twin, its gasless governance key could neither
    ///      hand the set back nor rotate itself — a mistaken hand-over (or a
    ///      lost key file) froze the set's governance forever. Proposing is
    ///      still not transferring: acceptance keeps requiring the PROPOSED
    ///      address (`acceptAdmin`, or `acceptAdminSigned` for an unfunded
    ///      key), so a relayer cannot install itself.
    function proposeAdminSigned(address newAdmin, uint256 nonce, Signature calldata sig) external {
        if (newAdmin == address(0)) revert ZeroAddress();
        _consume(OP_PROPOSE_ADMIN, bytes32(uint256(uint160(newAdmin))), nonce, sig, admin);
        pendingAdmin = newAdmin;
        emit AdminProposed(admin, newAdmin);
    }

    /// @notice Step 2 of the admin hand-over, signed by the pending admin and
    ///         relayed. The path that makes an unfunded governance key usable.
    function acceptAdminSigned(uint256 nonce, Signature calldata sig) external {
        address pa = pendingAdmin;
        if (pa == address(0)) revert NotPendingAdmin();
        // `expected` is the PENDING admin here, not the sitting one: this is the
        // one operation the current admin must not be able to sign for.
        _consume(OP_ACCEPT_ADMIN, bytes32(0), nonce, sig, pa);
        address previous = admin;
        admin = pa;
        pendingAdmin = address(0);
        emit AdminAccepted(previous, pa);
    }

    constructor(address initialAdmin, address[] memory initialCurators, uint256 initialThreshold) {
        require(initialAdmin != address(0), "CuratorSet: admin=0");
        admin = initialAdmin;
        emit AdminAccepted(address(0), initialAdmin);

        for (uint256 i = 0; i < initialCurators.length; i++) {
            _addCurator(initialCurators[i]);
        }

        _setThreshold(initialThreshold);
    }

    function addCurator(address curator) external onlyAdmin {
        _addCurator(curator);
    }

    function removeCurator(address curator) external onlyAdmin {
        _removeCurator(curator);
    }

    function _removeCurator(address curator) internal {
        require(curator != address(0), "CuratorSet: curator=0");
        require(_isCurator[curator], "CuratorSet: not curator");

        uint256 remaining = _curatorCount - 1;
        // Safety: do not silently lower the threshold. Require an explicit
        // setThreshold call first if removal would invalidate the threshold.
        if (_threshold > remaining) {
            revert ThresholdWouldExceedCurators(_threshold, remaining);
        }

        _isCurator[curator] = false;
        _curatorCount = remaining;
        emit CuratorRemoved(curator);
    }

    function setThreshold(uint256 t) external onlyAdmin {
        _setThreshold(t);
    }

    /// @notice Step 1 of 2-step admin transfer. Propose a new admin.
    /// @dev Pending admin must call acceptAdmin to complete the transfer.
    ///      The current admin remains in office until acceptance. The zero
    ///      address is rejected; a dedicated clear/cancel flow is not
    ///      provided in this contract.
    function proposeAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) {
            revert ZeroAddress();
        }
        pendingAdmin = newAdmin;
        emit AdminProposed(admin, newAdmin);
    }

    /// @notice Step 2 of 2-step admin transfer. Called by the pending admin.
    function acceptAdmin() external {
        address pa = pendingAdmin;
        if (pa == address(0) || msg.sender != pa) {
            revert NotPendingAdmin();
        }
        address previous = admin;
        admin = pa;
        pendingAdmin = address(0);
        emit AdminAccepted(previous, pa);
    }

    function isCurator(address who) external view returns (bool) {
        return _isCurator[who];
    }

    function getThreshold() external view returns (uint256) {
        return _threshold;
    }

    function getCuratorCount() external view returns (uint256) {
        return _curatorCount;
    }

    function _addCurator(address curator) internal {
        require(curator != address(0), "CuratorSet: curator=0");
        require(!_isCurator[curator], "CuratorSet: already curator");
        _isCurator[curator] = true;
        _curatorCount += 1;
        emit CuratorAdded(curator);
        // Note: when this is the first curator and threshold is still zero,
        // the threshold is left unchanged here on purpose. It MUST be set
        // explicitly via the constructor or setThreshold; this function
        // does not infer one automatically.
    }

    function _setThreshold(uint256 t) internal {
        require(_curatorCount > 0, "CuratorSet: no curators");
        require(t >= 1 && t <= _curatorCount, "CuratorSet: bad threshold");
        _threshold = t;
        emit ThresholdUpdated(t);
    }
}
